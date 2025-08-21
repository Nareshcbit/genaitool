AWS Network Reachability Judge — Deterministic Specification
1) Purpose & Scope

Goal: Given static inventory (nodes.jsonl, edges.jsonl) and a query (source → destination, protocol/port), determine if the source can initiate traffic to the destination, returning a strict JSON verdict: ALLOW | DENY | UNKNOWN, with the path, the matched route, SG/NACL matches, and the first blocking control.

No live AWS calls. No Network Access Analyzer. No LLM.

2) High-Level Architecture

Module A — Packet Builder (deterministic, streaming):
Reads large JSONL, resolves endpoints (EC2/Lambda/ECS → ENI), extracts only facts needed for this query (associated RT, candidate routes, SG/NACL subsets, minimal fabric hints). Produces a compact Reachability Packet JSON.

Module B — Judge (deterministic):
Consumes the packet and performs concrete checks:

Routing (longest-prefix from source associated RT)

Security Groups (stateful)

Network ACLs (stateless, forward & return)
Returns a structured verdict JSON.

Modules are decoupled so the packet can be inspected / stored for audit.

3) Interfaces
3.1 CLI

Packet Builder

packet_builder \
  --nodes nodes.jsonl \
  --edges edges.jsonl \
  --source-id <EC2|Lambda ARN|ECS task ARN|ENI|IP|Subnet> \
  --dest-id   <ENI|EC2|IP|Subnet> \
  --protocol tcp|udp \
  --port <1..65535> \
  [--prefer-secondary-eni] \
  [--ephemeral-low 1024] [--ephemeral-high 65535] \
  > packet.json


Judge (deterministic)

judge_deterministic \
  --packet packet.json \
  [--ephemeral-low 1024] [--ephemeral-high 65535] \
  > verdict.json


Exit codes: 0 success, 1 validation error, 2 processing error.

3.2 Library (optional)

build_packet(nodes_stream, edges_stream, query) -> dict

judge(packet_dict, eph_low=1024, eph_high=65535) -> dict

4) Inputs
4.1 Inventory (JSONL)

nodes.jsonl: one JSON per line. Recognized type (case-insensitive; aliases allowed):

instance (EC2), eni, subnet, vpc

sg (Security Group), nacl (Network ACL)

route-table (with routes[])

tgw, tgw-attachment, (optional) tgw-route-table, tgw-rt-association, tgw-rt-propagation

igw, natgw, vpc-peering

lambda (Function), ecs-task (task/ENI attachments)

(optional) vpce-gw, vpce-if

edges.jsonl: optional. If present, describes fabric relations (e.g., {"from":"rtb-...","to":"tgw-attach-...","kind":"route"}); Module A does not require it but may use as hints.

Field expectations (tolerant to naming):

ENI: id, private_ip|ip|PrimaryPrivateIpAddress, subnet_id|SubnetId, vpc_id|VpcId, security_groups|SecurityGroups|Groups (IDs or {"GroupId":...}).

Instance: id, network_interfaces|NetworkInterfaces (array with NetworkInterfaceId|eni_id + optional Primary).

Subnet: id, vpc_id|VpcId, cidr|cidr_block, nacl_id|network_acl_id|NaclId.

Route Table: id, vpc_id|VpcId, associations[] (main|Main, subnet_id|SubnetId), routes[]:

destination_cidr_block|CidrBlock, blackhole (bool),

target_type|gateway_type ∈ {local,igw,natgw,tgw,vgw,vpc-peering,eni},

target_id|gateway_id|eni_id.

SG: combined rules[] or split ingress[]/egress[]. Rule: direction (if combined), protocol|proto|"-1", from_port, to_port, cidr|cidr_block, sg_id|user_id_group_pairs, action|rule_action (allow|deny).

NACL: id, entries|rules[] with egress (bool), protocol|"-1", rule_action|action (allow|deny), port_range:{from,to}, cidr_block|cidr.

Lambda: id (ARN), vpc_config (may contain eni_ids, subnets, SGs).

ECS Task: id (ARN), attachments[] with NetworkInterfaceId|eni_id.

4.2 Query

source-id (EC2 id, Lambda ARN, ECS task ARN, ENI id, IP, or Subnet id)

dest-id (ENI id, EC2 id, IP, or Subnet id)

protocol ∈ {tcp,udp}

port ∈ [1..65535]

5) Module A — Packet Builder (deterministic)
Responsibilities

Resolve endpoints

Source: EC2/Lambda/ECS → ENI (primary if available). If IP or Subnet given, accept with partial context. Extract eni, ip, subnet, vpc, sgs[].

Destination: resolve to IP (prefer ENI/EC2 → IP). If only Subnet, mark IP missing.

Find associated Route Table

From source subnet explicit association; else VPC main RT.

If none: note SOURCE_ROUTE_TABLE_MISSING.

Select candidate routes

From the associated RT only:

keep routes whose CIDR contains destination IP (if known) plus default 0.0.0.0/0 or ::/0.

exclude blackhole.

record rtb, cidr, prefix_len, target_type, target_id.

sort by prefix_len desc.

If destination IP unknown: note inability to longest-prefix match.

Reduce SG rules

Source egress: rules where proto ∈ {packet.proto,"-1"}, port range includes <port>, and (CIDR contains dest IP or SG-ref ∈ dest SGs or rule has neither CIDR nor SG-ref = allow-all).

Dest ingress: symmetric for src IP / src SG.

Normalize user_id_group_pairs lists to group IDs.

Reduce NACL rules

For source subnet:

egress entries overlapping <port>; ingress overlapping ephemeral [EPH_LOW..EPH_HIGH].

For dest subnet:

ingress entries overlapping <port>; egress overlapping ephemeral.

Match protocol ∈ {packet.proto,"-1"}.

If subnet has no NACL object, packet records acl: null (judge treats as unknown; not implicit allow).

Fabric hints (optional but recommended)

If both VPCs are known, include:

TGW attachments linking the two VPCs (same TGW).

VPC peering between them.

IGWs on the source VPC (context for default routes).

Emit Reachability Packet

{
  "query": {"source_id":"...", "dest_id":"...", "protocol":"tcp", "port":443},
  "source": {"eni":"eni-...","ip":"10.1.2.3","subnet":"subnet-...","vpc":"vpc-...","sgs":["sg-..."],"associated_route_table":"rtb-..."},
  "dest":   {"eni":"eni-...","ip":"10.9.8.7","subnet":"subnet-...","vpc":"vpc-...","sgs":["sg-..."]},
  "candidate_routes_from_source": [
    {"rtb":"rtb-...","cidr":"10.9.0.0/16","prefix_len":16,"target_type":"tgw-attachment","target_id":"tgw-attach-...","blackhole":false}
  ],
  "security_groups": {
    "source_egress_rules":[{ /* normalized */ }],
    "dest_ingress_rules":[{ /* normalized */ }]
  },
  "nacls": {
    "source":{"acl":"acl-...","ingress_rules":[...],"egress_rules":[...]},
    "dest":{"acl":"acl-...","ingress_rules":[...],"egress_rules":[...]},
    "ephemeral_range":[1024,65535]
  },
  "fabric_hops": {"tgw":[...], "peerings":[...], "igws":[...]},
  "notes":[ "DESTINATION_IP_MISSING", "SOURCE_ROUTE_TABLE_MISSING", "…" ]
}


Performance: Must stream JSONL (no full-file load); stop early when possible.

6) Module B — Judge (deterministic)
Input

The Reachability Packet JSON from Module A.

Output (strict JSON)
{
  "decision": "ALLOW" | "DENY" | "UNKNOWN",
  "reason": "<one-line summary>",
  "path": ["<node-id>", "..."] | null,
  "controls": {
    "routing": {
      "matched_route": {"rtb":"rtb-...","cidr":"x/y","target_type":"...","target_id":"..."},
      "fabric": ["tgw-attach-...","tgw-...","pcx-..."]
    },
    "sg": {
      "source_egress": {"allowed": true|false, "match": {"sg_id":"sg-...","rule":{}}},
      "dest_ingress":  {"allowed": true|false, "match": {"sg_id":"sg-...","rule":{}}}
    },
    "nacl": {
      "source_egress_port": {"allowed": true|false, "subnet":"subnet-...","port": <int>},
      "dest_ingress_port":  {"allowed": true|false, "subnet":"subnet-...","port": <int>},
      "dest_egress_ephemeral": {"allowed": true|false, "subnet":"subnet-...","range":[<low>,<high>]},
      "source_ingress_ephemeral": {"allowed": true|false, "subnet":"subnet-...","range":[<low>,<high>]}
    }
  },
  "notes": ["..."]
}

Algorithm

Validate packet

Require: protocol, port, source.subnet or source.vpc, and either dest.ip or a clear note explaining absence.

If missing critical facts (e.g., source.associated_route_table OR dest.ip), return UNKNOWN with notes (do not guess).

Routing (forward only)

From candidate_routes_from_source, select the longest-prefix entry that contains dest.ip.

If none:

if a default route is present, treat as match only when the route’s target is meaningful for private reachability:

igw/natgw: not valid for reaching a private ENI in another VPC → DENY (routing) unless dest.ip is public and policy allows (out of scope unless packet marks public).

tgw-attachment or vpc-peering: valid fabric next-hops.

local: valid only if source & dest are same VPC and dest.ip within VPC CIDR.

else DENY (routing).

Set controls.routing.matched_route to chosen route; populate fabric from packet fabric_hops if relevant.

Security Groups (stateful)

Source egress: allowed if any rule in security_groups.source_egress_rules matches (already prefiltered). Record exact rule for match.

Dest ingress: allowed if any rule in security_groups.dest_ingress_rules matches.

If either side has zero matching rules → DENY (SG egress/ingress) accordingly.

Network ACLs (stateless)

Use packet nacls.ephemeral_range = [L,H] (default [1024,65535] if absent).

Forward:

source.egress_rules must contain an allow overlapping <port>;

dest.ingress_rules must contain an allow overlapping <port>.

Return:

dest.egress_rules must contain an allow overlapping [L,H];

source.ingress_rules must contain an allow overlapping [L,H].

If a subnet’s NACL is null or no entries → treat as UNKNOWN (cannot infer AWS default) unless your data explicitly represents default-allow; otherwise DENY (NACL) only when there are explicit deny-only or no allow entries in presence of an explicit NACL. Record first failing check under controls.nacl.* and pick first failure as the decision reason.

Decision priority

If any step is indeterminate due to missing facts → UNKNOWN (include notes).

Else, if routing fails → DENY (routing).

Else, if SG egress/ingress fails → DENY (SG …).

Else, if any NACL leg fails → DENY (NACL …).

Else → ALLOW.

Path reconstruction (best-effort)

Compose path from: source.eni → source.subnet → source.associated_route_table → (matched next-hop) → fabric hints → dest.subnet → dest.eni.

If destination is IP-only (no ENI), end at dest.subnet if known; otherwise set path=null.

7) Non-Functional Requirements

Performance: Stream JSONL, avoid O(N) re-reads where possible; packet build for typical queries in seconds even with >1M lines.

Determinism: Same inputs ⇒ same output.

Robustness: Tolerant to field name variations; never crash on absent optional sections.

Observability: Verbose mode logs selection decisions (e.g., chosen route, rule IDs) without dumping entire inventories.

Security: No network calls. No secrets processed.

8) Error Handling

Invalid CLI args / port out of range ⇒ exit 1.

JSON parse error on a line ⇒ log line number; skip; continue.

Missing critical facts ⇒ packet includes explicit notes; Judge returns UNKNOWN with those notes.

Conflicting data (e.g., two “main” RTs) ⇒ prefer deterministic tie-break (first seen); add note.

9) Testing & Acceptance
Unit

Route longest-prefix selection; default route behaviors.

SG parsing: user_id_group_pairs objects; CIDR vs SG-ref; -1 protocol.

NACL overlap and direction correctness; explicit deny precedence where represented.

Endpoint resolution for EC2/Lambda/ECS → ENI.

Integration Fixtures (expected decisions)

Intra-VPC allow: local route; SG egress+ingress allow; NACLs allow → ALLOW.

SG ingress block: path exists; dest ingress missing → DENY (SG ingress).

NACL return block: forward ok; dest egress ephemeral missing → DENY (NACL return).

No route: no matching or usable default route → DENY (routing).

Unknown: dest IP missing or no associated/main RT → UNKNOWN with notes.

All fixtures must match the exact verdict and populate the corresponding controls.* fields.

10) Deliverables

packet_builder CLI + library function (streaming JSONL).

judge_deterministic CLI + library function implementing the algorithm above.

Example fixtures (nodes.jsonl, edges.jsonl, queries) with expected packet.json and verdict.json.

README describing quickstart, field mappings, and the deterministic checks.

If you want, I can generate a reference judge_deterministic.py that consumes the packet and implements the exact algorithm/priority order above.