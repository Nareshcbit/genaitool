#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
reachability_packet_builder.py

Build a compact "reachability packet" for LLM judgment from flexible inputs:
- Source or destination can be: EC2 instance, ENI, Subnet, VPC, TGW-Attachment, or TGW.
- Produces a minimal, LLM-friendly JSON containing:
  - query (eni_a/b, protocol/port)
  - resolved endpoint facts (ip, subnet, vpc, sgs, associated route-table)
  - candidate routes from the source side (longest-prefix candidates toward dest ip)
  - fabric hops (TGW attachments/peerings/etc) needed to cross VPC boundaries
  - filtered SG/NACL rules relevant to the query

Usage:
  python reachability_packet_builder.py \
    --nodes nodes.json --edges edges.json \
    --source-id i-0123abcd... \
    --dest-id eni-0abc... \
    --port 443 --protocol tcp \
    > packet.json

Then send packet.json to your Bedrock/Claude LLM using your existing prompt.

Notes:
- This is best-effort and tolerant to varied export schemas. Unknown fields become null and get notes[].
- If the "source" isn’t an ENI/EC2, IP may be unknown; SG/NACL sections will be partial.
"""

import argparse, json, ipaddress, sys
from typing import Any, Dict, List, Optional, Tuple, Set
from collections import defaultdict

# -------------------------
# Helpers: schema tolerance
# -------------------------

def ntype(n: Dict[str, Any]) -> str:
    return (n.get("type") or n.get("Type") or n.get("kind") or "").lower()

def index_nodes(nodes: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    idx = {}
    for n in nodes:
        nid = n.get("id") or n.get("ID") or n.get("arn") or n.get("name")
        if nid: idx[nid] = n
    return idx

def find_by_id(nodes: Dict[str, Dict[str, Any]], nid: str) -> Optional[Dict[str, Any]]:
    if nid in nodes: return nodes[nid]
    # loose fallback: match suffix
    for k, v in nodes.items():
        if k.endswith(nid): return v
    return None

def get_field(n: Dict[str, Any], *keys, default=None):
    for k in keys:
        if k in n: return n[k]
    return default

def eni_ip(eni: Dict[str, Any]) -> Optional[str]:
    return get_field(eni, "private_ip", "ip", "primary_private_ip", default=None)

def eni_sgs(eni: Dict[str, Any]) -> List[str]:
    sgs = get_field(eni, "security_groups", "sgs", "SecurityGroups", default=[])
    return sgs if isinstance(sgs, list) else []

def eni_subnet(eni: Dict[str, Any]) -> Optional[str]:
    return get_field(eni, "subnet_id", "SubnetId", "subnet", default=None)

def subnet_vpc(subnet: Dict[str, Any]) -> Optional[str]:
    return get_field(subnet, "vpc_id", "VpcId", "vpc", default=None)

def subnet_cidr(subnet: Dict[str, Any]) -> Optional[str]:
    return get_field(subnet, "cidr", "cidr_block", "CidrBlock", default=None)

def subnet_nacl_id(subnet: Dict[str, Any]) -> Optional[str]:
    return get_field(subnet, "nacl_id", "network_acl_id", "NaclId", default=None)

def vpc_cidr(vpc: Dict[str, Any]) -> Optional[str]:
    return get_field(vpc, "cidr", "cidr_block", "CidrBlock", default=None)

def instance_enis(instance: Dict[str, Any]) -> List[str]:
    # Try common shapes
    enis = []
    attachments = get_field(instance, "network_interfaces", "NetworkInterfaces", default=[])
    if isinstance(attachments, list):
        for a in attachments:
            eni_id = get_field(a, "eni_id", "network_interface_id", "id")
            if eni_id: enis.append(eni_id)
    # alt: direct "primary_eni"/"eni"
    for k in ("eni", "primary_eni", "PrimaryNetworkInterfaceId"):
        v = instance.get(k)
        if isinstance(v, str): enis.append(v)
    # dedupe
    return list(dict.fromkeys(enis))

def route_table_associations(rt: Dict[str, Any]) -> List[Dict[str, Any]]:
    return get_field(rt, "associations", "Associations", default=[])

def route_table_routes(rt: Dict[str, Any]) -> List[Dict[str, Any]]:
    return get_field(rt, "routes", "Routes", default=[])

def is_main_assoc(assoc: Dict[str, Any]) -> bool:
    return bool(get_field(assoc, "main", "Main", default=False))

def assoc_subnet_id(assoc: Dict[str, Any]) -> Optional[str]:
    return get_field(assoc, "subnet_id", "SubnetId", default=None)

def route_dest_cidr(route: Dict[str, Any]) -> Optional[str]:
    return get_field(route, "destination_cidr_block", "DestinationCidrBlock", "cidr", "CidrBlock", default=None)

def route_blackhole(route: Dict[str, Any]) -> bool:
    return bool(get_field(route, "blackhole", "Blackhole", default=False))

def route_target_type(route: Dict[str, Any]) -> Optional[str]:
    return (get_field(route, "target_type", "TargetType", "gateway_type", "GatewayType", default=None) or "").lower()

def route_target_id(route: Dict[str, Any]) -> Optional[str]:
    return get_field(route, "target_id", "TargetId", "gateway_id", "GatewayId", "eni_id", "NetworkInterfaceId", default=None)

def route_local(route: Dict[str, Any]) -> bool:
    t = route_target_type(route)
    if t: return t in ("local", "vpc-local")
    # Some exports mark "gateway_id": "local"
    gid = (route_target_id(route) or "").lower()
    return gid == "local"

def ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False

def prefix_len(cidr: str) -> int:
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen
    except Exception:
        return -1

# -------------------------
# Graph/linkage utilities
# -------------------------

ALIASES = {
    "instance": {"instance", "ec2", "ec2-instance"},
    "eni": {"eni", "network-interface"},
    "subnet": {"subnet"},
    "vpc": {"vpc"},
    "rtb": {"route-table", "routetable", "rtb"},
    "tgw": {"tgw", "transit-gateway"},
    "tgw-attachment": {"tgw-attachment", "transit-gateway-attachment"},
    "peering": {"vpc-peering", "peering"},
    "igw": {"igw", "internet-gateway"},
    "natgw": {"natgw", "nat-gateway"},
    "nacl": {"nacl", "network-acl"},
    "sg": {"sg", "security-group"},
    "vpce-gw": {"gateway-endpoint", "vpce-gw"},
    "vpce-if": {"interface-endpoint", "vpce-if"},
}

def is_type(n: Dict[str, Any], want: str) -> bool:
    t = ntype(n)
    return any(t == alias for alias in ALIASES.get(want, {want}))

def group_by_type(nodes: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    g = defaultdict(list)
    for n in nodes:
        g[ntype(n)].append(n)
    return g

def find_main_rtb_for_vpc(vpc_id: str, rts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for rt in rts:
        if get_field(rt, "vpc_id", "VpcId", default=None) == vpc_id:
            if any(is_main_assoc(a) for a in route_table_associations(rt)):
                return rt
    return None

def find_rtb_for_subnet(subnet_id: str, rts: List[Dict[str, Any]], vpc_main: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for rt in rts:
        for a in route_table_associations(rt):
            if assoc_subnet_id(a) == subnet_id:
                return rt
    return vpc_main

def all_sgs(nodes_by_id: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {nid: n for nid, n in nodes_by_id.items() if is_type(n, "sg")}

def all_nacls(nodes_by_id: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {nid: n for nid, n in nodes_by_id.items() if is_type(n, "nacl")}

def normalize_sg_rules(sg: Dict[str, Any]) -> List[Dict[str, Any]]:
    rules = []
    base = sg.get("rules")
    if isinstance(base, list): rules.extend(base)
    for key in ("ingress", "egress", "Ingress", "Egress"):
        if isinstance(sg.get(key), list):
            for r in sg[key]:
                rr = dict(r); rr["direction"] = key.lower()
                rules.append(rr)
    out = []
    for r in rules:
        out.append({
            "direction": (r.get("direction") or "ingress").lower(),
            "proto": (r.get("protocol") or r.get("proto") or "-1").lower(),
            "from": r.get("from_port"),
            "to": r.get("to_port"),
            "cidr": r.get("cidr") or r.get("cidr_block"),
            "sg_ref": r.get("sg_id") or r.get("source_sg") or r.get("user_id_group_pairs"),
            "action": (r.get("action") or r.get("rule_action") or "allow").lower()
        })
    return out

def normalize_nacl_entries(nacl: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    entries = nacl.get("entries") or nacl.get("rules") or []
    ing, eg = [], []
    for e in entries:
        entry = {
            "egress": bool(e.get("egress", False)),
            "proto": (e.get("protocol") or "-1").lower(),
            "action": (e.get("rule_action") or e.get("action") or "allow").lower(),
            "from": (e.get("port_range") or {}).get("from"),
            "to": (e.get("port_range") or {}).get("to"),
            "cidr": e.get("cidr_block") or e.get("cidr")
        }
        (eg if entry["egress"] else ing).append(entry)
    return {"ingress": ing, "egress": eg}

# -------------------------
# Resolution of endpoints
# -------------------------

def resolve_endpoint(nodes_by_id: Dict[str, Dict[str, Any]],
                     nodes_by_type: Dict[str, List[Dict[str, Any]]],
                     raw_id: str,
                     prefer_primary_eni: bool = True) -> Tuple[Optional[str], Dict[str, Any], List[str]]:
    """
    Return (endpoint_kind, facts, notes)
    endpoint_kind in {"eni","instance","subnet","vpc","tgw-attachment","tgw"}
    facts contain best-effort fields: eni, ip, subnet, subnet_cidr, vpc, sgs, associated_route_table
    """
    notes = []
    n = find_by_id(nodes_by_id, raw_id)
    if not n:
        return None, {}, [f"Node {raw_id} not found"]

    t = ntype(n)

    # If user passed an instance: pick primary ENI if possible
    if t in ALIASES["instance"]:
        enis = instance_enis(n)
        if not enis:
            notes.append(f"Instance {raw_id} has no attached ENIs in inventory")
            return "instance", {"instance": raw_id}, notes
        eni_id = enis[0] if prefer_primary_eni else enis[-1]
        eni = find_by_id(nodes_by_id, eni_id)
        if not eni:
            notes.append(f"Primary ENI {eni_id} not found; falling back to instance-level facts")
            return "instance", {"instance": raw_id}, notes
        t = "eni"
        n = eni
        raw_id = eni_id

    if t in ALIASES["eni"]:
        facts = {
            "eni": raw_id,
            "ip": eni_ip(n),
            "subnet": eni_subnet(n),
            "vpc": None,  # fill from subnet
            "sgs": eni_sgs(n),
            "subnet_cidr": None,
            "associated_route_table": None
        }
        # enrich subnet & vpc & rtb
        sub = find_by_id(nodes_by_id, facts["subnet"]) if facts["subnet"] else None
        if sub:
            facts["vpc"] = subnet_vpc(sub)
            facts["subnet_cidr"] = subnet_cidr(sub)
            vpc_main = find_main_rtb_for_vpc(facts["vpc"], nodes_by_type.get("route-table", []) + nodes_by_type.get("routetable", []) + nodes_by_type.get("rtb", []))
            rtb = find_rtb_for_subnet(facts["subnet"],
                                      nodes_by_type.get("route-table", []) + nodes_by_type.get("routetable", []) + nodes_by_type.get("rtb", []),
                                      vpc_main)
            if rtb: facts["associated_route_table"] = rtb.get("id")
        else:
            notes.append(f"Subnet not found for ENI {raw_id}")
        return "eni", facts, notes

    if t in ALIASES["subnet"]:
        facts = {
            "eni": None, "ip": None,
            "subnet": n.get("id"),
            "subnet_cidr": subnet_cidr(n),
            "vpc": subnet_vpc(n),
            "sgs": [],
            "associated_route_table": None
        }
        vpc_main = find_main_rtb_for_vpc(facts["vpc"], nodes_by_type.get("route-table", []) + nodes_by_type.get("routetable", []) + nodes_by_type.get("rtb", []))
        rtb = find_rtb_for_subnet(facts["subnet"],
                                  nodes_by_type.get("route-table", []) + nodes_by_type.get("routetable", []) + nodes_by_type.get("rtb", []),
                                  vpc_main)
        if rtb: facts["associated_route_table"] = rtb.get("id")
        notes.append("Source is subnet; ENI/IP unknown, SG evaluation will be partial")
        return "subnet", facts, notes

    if t in ALIASES["vpc"]:
        facts = {
            "eni": None, "ip": None,
            "subnet": None, "subnet_cidr": None,
            "vpc": n.get("id"),
            "sgs": [],
            "associated_route_table": None
        }
        notes.append("Source is VPC; no specific subnet/ENI supplied—routing will be coarse, SG/NACL unknown")
        return "vpc", facts, notes

    if t in ALIASES["tgw-attachment"]:
        facts = {
            "tgw_attachment": n.get("id"),
            "tgw_id": get_field(n, "tgw_id", "TransitGatewayId", default=None),
            "vpc": get_field(n, "vpc_id", "VpcId", default=None)
        }
        notes.append("Source is TGW attachment; no ENI/IP. Will build fabric context only.")
        return "tgw-attachment", facts, notes

    if t in ALIASES["tgw"]:
        facts = {"tgw_id": n.get("id")}
        notes.append("Source is TGW; fabric-only context")
        return "tgw", facts, notes

    return t, {"raw_id": raw_id}, [f"Unrecognized or unsupported type {t} for {raw_id}"]

# -------------------------
# Route candidate filtering
# -------------------------

def candidate_routes_from_source(nodes_by_id: Dict[str, Dict[str, Any]],
                                 nodes_by_type: Dict[str, List[Dict[str, Any]]],
                                 source_facts: Dict[str, Any],
                                 dest_ip: Optional[str]) -> List[Dict[str, Any]]:
    if not dest_ip:
        return []

    rts = nodes_by_type.get("route-table", []) + nodes_by_type.get("routetable", []) + nodes_by_type.get("rtb", [])
    rtb_id = source_facts.get("associated_route_table")
    if not rtb_id:
        return []

    rtb = find_by_id(nodes_by_id, rtb_id)
    if not rtb:
        return []

    cands = []
    for r in route_table_routes(rtb):
        if route_blackhole(r): continue
        cidr = route_dest_cidr(r)
        if not cidr: continue
        if ip_in_cidr(dest_ip, cidr) or cidr == "0.0.0.0/0" or cidr == "::/0":
            cands.append({
                "rtb": rtb_id,
                "cidr": cidr,
                "prefix_len": prefix_len(cidr),
                "target_type": (route_target_type(r) or ("local" if route_local(r) else None)),
                "target_id": route_target_id(r),
                "blackhole": False
            })
    # Prefer more specific first when LLM reads
    cands.sort(key=lambda x: x["prefix_len"], reverse=True)
    return cands

# -------------------------
# SG/NACL filtering (tiny)
# -------------------------

def filter_sg_rules_for_query(sg_nodes: Dict[str, Dict[str, Any]],
                              src_sgs: List[str],
                              dst_sgs: List[str],
                              proto: str,
                              port: int,
                              src_ip: Optional[str],
                              dst_ip: Optional[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    egress_rules = []
    ingress_rules = []

    def rule_matches(r: Dict[str, Any], direction: str) -> bool:
        if (r.get("direction") or "ingress") != direction: return False
        rp = (r.get("proto") or "-1").lower()
        if rp not in (proto, "-1", "all", "any"): return False
        f = r.get("from"); t = r.get("to")
        if f is not None and t is not None and not (f <= port <= t): return False
        if f is None and t is None:
            pass  # any port
        cidr = r.get("cidr")
        sgref = r.get("sg_ref")
        cidr_ok = (cidr is None) or (src_ip and dst_ip and (ip_in_cidr(dst_ip if direction=="egress" else src_ip, cidr)))
        sg_ok = False
        if sgref:
            if isinstance(sgref, list):
                sg_ok = any(s in (dst_sgs if direction=="egress" else src_sgs) for s in sgref)
            else:
                sg_ok = (sgref in (dst_sgs if direction=="egress" else src_sgs))
        return (r.get("action","allow") == "allow") and (cidr_ok or sg_ok or (cidr is None and sgref is None))

    for sg_id in src_sgs:
        sg = sg_nodes.get(sg_id)
        if not sg: continue
        for r in normalize_sg_rules(sg):
            if rule_matches(r, "egress"):
                egress_rules.append({"sg": sg_id, **r})
    for sg_id in dst_sgs:
        sg = sg_nodes.get(sg_id)
        if not sg: continue
        for r in normalize_sg_rules(sg):
            if rule_matches(r, "ingress"):
                ingress_rules.append({"sg": sg_id, **r})

    return egress_rules, ingress_rules

def filter_nacl_rules_for_query(nacl_nodes: Dict[str, Dict[str, Any]],
                                subnet_nodes: Dict[str, Dict[str, Any]],
                                src_subnet_id: Optional[str],
                                dst_subnet_id: Optional[str],
                                proto: str,
                                port: int) -> Dict[str, Any]:
    EPH_LOW, EPH_HIGH = 1024, 65535
    out = {"source": None, "dest": None}
    if src_subnet_id:
        src_sub = subnet_nodes.get(src_subnet_id)
        if src_sub:
            acl_id = subnet_nacl_id(src_sub)
            acl = nacl_nodes.get(acl_id) if acl_id else None
            if acl:
                ent = normalize_nacl_entries(acl)
                out["source"] = {
                    "subnet": src_subnet_id,
                    "acl": acl_id,
                    "egress_rules": [e for e in ent["egress"] if (e["proto"] in (proto,"-1") and (e["from"] is None or e["from"] <= port) and (e["to"] is None or port <= e["to"]))],
                    "ingress_rules": [e for e in ent["ingress"] if (e["proto"] in (proto,"-1") and (e["from"] is None or e["from"] <= EPH_LOW) and (e["to"] is None or EPH_HIGH <= e["to"]))],
                }
    if dst_subnet_id:
        dst_sub = subnet_nodes.get(dst_subnet_id)
        if dst_sub:
            acl_id = subnet_nacl_id(dst_sub)
            acl = nacl_nodes.get(acl_id) if acl_id else None
            if acl:
                ent = normalize_nacl_entries(acl)
                out["dest"] = {
                    "subnet": dst_subnet_id,
                    "acl": acl_id,
                    "ingress_rules": [e for e in ent["ingress"] if (e["proto"] in (proto,"-1") and (e["from"] is None or e["from"] <= port) and (e["to"] is None or port <= e["to"]))],
                    "egress_rules": [e for e in ent["egress"] if (e["proto"] in (proto,"-1") and (e["from"] is None or e["from"] <= EPH_LOW) and (e["to"] is None or EPH_HIGH <= e["to"]))],
                }
    return out

# -------------------------
# Fabric hints (TGW/Peering)
# -------------------------

def build_fabric_hints(nodes_by_id: Dict[str, Dict[str, Any]],
                       nodes_by_type: Dict[str, List[Dict[str, Any]]],
                       source_facts: Dict[str, Any],
                       dest_facts: Dict[str, Any]) -> Dict[str, Any]:
    hints = {
        "tgw": [],
        "peerings": [],
        "nat_gateways": [],
        "igws": []
    }
    # TGW attachments connected to either VPC
    src_vpc = source_facts.get("vpc")
    dst_vpc = dest_facts.get("vpc")
    atts = nodes_by_type.get("tgw-attachment", [])
    for a in atts:
        vpc_id = get_field(a, "vpc_id", "VpcId", default=None)
        tgw_id = get_field(a, "tgw_id", "TransitGatewayId", default=None)
        if not tgw_id: continue
        if vpc_id in (src_vpc, dst_vpc):
            # find peer attachments on same TGW that connect to the other VPC
            for b in atts:
                if a is b: continue
                if get_field(b, "tgw_id", "TransitGatewayId", default=None) == tgw_id and get_field(b, "vpc_id", "VpcId", default=None) in (src_vpc, dst_vpc):
                    hints["tgw"].append({
                        "attachment": a.get("id"),
                        "tgw_id": tgw_id,
                        "peer_attachment": b.get("id"),
                        "peer_vpc": get_field(b, "vpc_id", "VpcId", default=None)
                    })
    # VPC peering between src/dst
    peers = nodes_by_type.get("vpc-peering", []) + nodes_by_type.get("peering", [])
    for p in peers:
        a = get_field(p, "vpc_id_a", "RequesterVpcId", default=None)
        b = get_field(p, "vpc_id_b", "AccepterVpcId", default=None)
        if {a,b} == {src_vpc, dst_vpc}:
            hints["peerings"].append({"peering": p.get("id"), "vpc_a": a, "vpc_b": b})
    # IGWs connected to src VPC (for 0.0.0.0/0 routes)
    igws = nodes_by_type.get("igw", [])
    for igw in igws:
        # many exports connect IGW to VPC via "attachments" array
        atts = igw.get("attachments") or []
        if any(get_field(x, "vpc_id", "VpcId", default=None) == src_vpc for x in atts):
            hints["igws"].append(igw.get("id"))
    return hints

# -------------------------
# Main packet builder
# -------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", required=True)
    ap.add_argument("--edges", required=False, help="Optional; not required for packet building")
    ap.add_argument("--source-id", required=True, help="Can be EC2/ENI/Subnet/VPC/TGW-Attachment/TGW id")
    ap.add_argument("--dest-id", required=True, help="Usually ENI or EC2, but subnet/vpc supported")
    ap.add_argument("--protocol", default="tcp", choices=["tcp","udp"])
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--prefer-secondary-eni", action="store_true", help="If source is instance with multiple ENIs")
    args = ap.parse_args()

    raw_nodes = json.load(open(args.nodes, "r", encoding="utf-8"))
    nodes = raw_nodes.get("nodes", raw_nodes) if isinstance(raw_nodes, dict) else raw_nodes
    nodes_by_id = index_nodes(nodes)
    by_type = group_by_type(nodes)

    # Resolve source & destination endpoints
    src_kind, src_facts, src_notes = resolve_endpoint(nodes_by_id, by_type, args.source_id, prefer_primary_eni=not args.prefer_secondary_eni)
    dst_kind, dst_facts, dst_notes = resolve_endpoint(nodes_by_id, by_type, args.dest_id, prefer_primary_eni=True)

    # For destination, try to ensure we have IP (LLM needs an IP for prefix matching)
    dst_ip = dst_facts.get("ip")
    if not dst_ip and dst_facts.get("eni"):
        eni = nodes_by_id.get(dst_facts["eni"])
        dst_ip = eni_ip(eni) if eni else None
        dst_facts["ip"] = dst_ip
    if not dst_ip and dst_facts.get("subnet") and vpc_cidr_id := dst_facts.get("subnet_cidr"):
        # leave None; LLM will mark UNKNOWN
        pass

    # Candidate routes from source associated RT
    cands = candidate_routes_from_source(nodes_by_id, by_type, src_facts, dst_ip)

    # SG / NACL filtering
    sg_nodes = all_sgs(nodes_by_id)
    nacl_nodes = all_nacls(nodes_by_id)
    subnet_nodes = {nid: n for nid, n in nodes_by_id.items() if is_type(n, "subnet")}

    src_sgs = src_facts.get("sgs") or []
    dst_sgs = dst_facts.get("sgs") or []
    egress_rules, ingress_rules = filter_sg_rules_for_query(
        sg_nodes, src_sgs, dst_sgs, args.protocol, args.port, src_facts.get("ip"), dst_ip
    )

    nacl_info = filter_nacl_rules_for_query(
        nacl_nodes, subnet_nodes, src_facts.get("subnet"), dst_facts.get("subnet"), args.protocol, args.port
    )

    # Fabric hints (TGW/Peering/IGW)
    fabric = build_fabric_hints(nodes_by_id, by_type, src_facts, dst_facts)

    packet = {
        "query": {
            "source_id": args.source_id,
            "dest_id": args.dest_id,
            "protocol": args.protocol,
            "port": args.port
        },
        "source": src_facts,
        "dest": dst_facts,
        "candidate_routes_from_source": cands,
        "fabric_hops": fabric,
        "security_groups": {
            "source_egress_rules": egress_rules,
            "dest_ingress_rules": ingress_rules
        },
        "nacls": nacl_info,
        "notes": (src_notes or []) + (dst_notes or [])
    }

    print(json.dumps(packet, indent=2))

if __name__ == "__main__":
    main()
