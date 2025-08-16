Prompt to Q — Part 5: Shadow Validation Against AWS (Read-Only)

Role: You are a senior cloud platform engineer. Create a read-only, local-first shadow validation setup that pulls data from a small AWS sandbox, runs our pipeline entirely on my laptop, and cross-checks results with Reachability Analyzer (and optionally Network Access Analyzer). No app deployment yet.

Context

I already have Parts 1–4 (schemas, local stack, fixtures, tests) and Part 6 views/Part 8 evaluator.

I want a tiny sandbox AWS account topology provisioned once with Terraform.

Then I will assume a read-only role, run code locally to:

call Describe*/TGW APIs → Parquet (S3 optional; local disk OK),

run ETL → nodes.jsonl / edges.jsonl,

load into local Neo4j (Docker),

run reachability(),

compare with Reachability Analyzer (CreatePath) and output a diff report.

Deliverables (generate all files with full contents)
A) Terraform: minimal sandbox topology (infra/terraform/)

Providers & variables, remote state optional.

Resources (use smallest instances and count=1):

VPC-A (10.0.0.0/16), private Subnet-A, RT-A (default LOCAL + route to TGW).

VPC-B (10.20.0.0/16), private Subnet-B, RT-B (LOCAL + route to TGW).

Transit Gateway, TGW attachments for VPC-A and VPC-B, TGW route table with route 10.20.0.0/16 → attach-B.

Two EC2 t4g.nano (or t3.nano) instances (one in each subnet) with SGs allowing tcp/443 between them.

Negative path: create a second pair (Subnets/ENIs) or toggle a variable to remove B’s return route to force asymmetry.

Outputs:

eni_a_id, eni_b_id, eni_a_ip, eni_b_ip, tgw_rt_id, attach_a_id, attach_b_id, security group IDs.

Separate variables (var.make_asymmetric) to flip return route off for the failing scenario.

A read-only IAM role + inline policy (see Section C) to be assumed by local user for Describe*/Reachability.

B) Local runner scripts (shadow/)

Create a small local CLI (Python) to perform the shadow validation:

shadow/pull_inventory.py

Uses boto3 with STS AssumeRole to the read-only role (env vars or --role-arn, --session-name).

Calls:

ec2:DescribeVpcs/Subnets/RouteTables/SecurityGroups/NetworkAcls/NetworkInterfaces/InternetGateways/NatGateways/VpcPeeringConnections/TransitGateways/TransitGatewayAttachments/TransitGatewayRouteTables

ec2:SearchTransitGatewayRoutes, ec2:DescribePrefixLists

ec2:DescribeVpcEndpoints

Reachability Analyzer: none here (that’s in compare step).

Writes raw JSON to ./out/aws_raw/…jsonl and Parquet to ./out/parquet/…parquet (use pyarrow).

Emits a manifest.json with account, regions, and timestamps.

shadow/run_etl.py

Reuses our DuckDB shim (Part 2/6): runs SQL to create vw_* views from parquet; exports nodes.jsonl and edges.jsonl to ./out/graph/.

shadow/load_graph.py

Loads JSONL into local Neo4j via Bolt using the UNWIND/MERGE patterns from Part 5 (upserts).

Verifies basic shapes (counts, sample queries); prints a summary table.

shadow/reachability_compare.py

Inputs: eni_a, eni_b, proto, port.

Local engine: calls our reachable() and captures: decision, path nodes/edges, evidence.

AWS Reachability Analyzer:

Creates a one-off path via CreatePath with Source={VpcEndpoint|NetworkInterfaceId: eni_a}, Destination={NetworkInterfaceId: eni_b}, Protocol, DestinationPort.

Polls GetPathAnalysis until Status terminal; captures PathFound and hop list.

Diff report:

Compares Decision (reachable vs ReachabilityStatus), and Hops (by type/order if possible).

If mismatch: prints a human-readable diff + writes ./out/diff/diff_YYYYMMDD_HHMMSS.json (see schema in Section E).

Optional: Network Access Analyzer template call (if present): run and attach results to the diff report.

shadow/cli.py

Click/Typer CLI wrapper with commands:

pull-inventory, etl, load-graph, compare --eni-a ... --eni-b ... --proto tcp --port 443, and all (runs everything).

Global options: --role-arn, --profile, --region, --athena (future), --out ./out.

C) IAM: read-only role & policy (infra/iam/)

read_only_role.tf: IAM role + trust policy allowing your principal (or OIDC/GitHub if desired) to assume.

Managed policies to attach (or inline JSON):

AmazonEC2ReadOnlyAccess (covers most Describe*).

AmazonVPCReadOnlyAccess.

AmazonSSMReadOnlyAccess (optional).

Add explicit actions for Reachability Analyzer:

ec2:CreateNetworkInsightsPath, ec2:DeleteNetworkInsightsPath, ec2:StartNetworkInsightsAnalysis, ec2:DescribeNetworkInsightsAnalyses, ec2:DescribeNetworkInsightsPaths.

STS AssumeRole permission for your user/role.

Output the role_arn.

D) Makefile & README updates

Make targets:

make tf_init && make tf_apply (Terraform sandbox)

make shadow_pull (assume role, pull Describe*, write parquet)

make shadow_etl (DuckDB → JSONL)

make shadow_load (load Neo4j)

make shadow_compare PASS=1 (compare path expected to pass)

make shadow_compare FAIL=1 (flip make_asymmetric=true then compare expected to fail)

README section: step-by-step usage, including how to export AWS credentials or pass --role-arn.

E) Diff report format (out/diff/*.json)

Provide a schema and an example:

{
  "generator": "shadow-validate/v1",
  "runAt": "2025-08-16T12:34:56Z",
  "inputs": {
    "srcEni": "eni-aaa",
    "dstEni": "eni-bbb",
    "proto": "tcp",
    "port": 443,
    "region": "us-east-1",
    "roleArn": "arn:aws:iam::111111111111:role/ReachabilityReadOnly"
  },
  "localDecision": {
    "reachable": true,
    "pathNodes": ["eni-aaa","subnet-a","rtb-a","tgw-attach-a","tgw-rt-1","tgw-attach-b","rtb-b","subnet-b","eni-bbb"],
    "reasons": ["rtb-a 10.20.0.0/16 -> tgw-attach-a", "tgw-rt-1 10.20.0.0/16 -> tgw-attach-b", "SG/NACL allow tcp/443"]
  },
  "awsDecision": {
    "reachabilityStatus": "reachable",
    "hops": ["eni-aaa","subnet-a","rtb-a","tgw-attach-a","tgw-rt-1","tgw-attach-b","rtb-b","subnet-b","eni-bbb"]
  },
  "match": true,
  "mismatches": [],
  "notes": "Local and AWS results agree."
}


If mismatched, include entries like:

{
  "code": "L3_DIFF",
  "local": {"edge":"rtb-a -> tgw-attach-a", "destCidr":"10.20.0.0/16"},
  "aws":   {"edge":"rtb-a -> blackhole", "reason":"no propagation"},
  "hint": "Check TGW propagation and association."
}

F) Safety & cleanup

shadow/reachability_compare.py must DeleteNetworkInsightsPath after analysis to avoid quota clutter.

Provide exponential backoff and max wait (e.g., 60s) for analysis completion.

Clearly label the Terraform with low-cost defaults and a destroy target.

G) Example commands (document and include in README)
# 0) One-time sandbox (cheap)
cd infra/terraform && terraform init && terraform apply -auto-approve

# 1) Pull inventory (read-only)
python -m shadow.cli pull-inventory --role-arn arn:aws:iam::111111111111:role/ReachabilityReadOnly --region us-east-1

# 2) ETL → JSONL
python -m shadow.cli etl

# 3) Load local Neo4j
python -m shadow.cli load-graph

# 4) Compare for the PASS case
python -m shadow.cli compare --eni-a $(terraform output -raw eni_a_id) --eni-b $(terraform output -raw eni_b_id) --proto tcp --port 443

# 5) Flip to FAIL (asymmetry), re-apply and compare again
terraform apply -auto-approve -var="make_asymmetric=true"
python -m shadow.cli compare --eni-a ... --eni-b ... --proto tcp --port 443

H) Acceptance Criteria

Terraform stands up a tiny TGW A↔B topology with a toggle to induce asymmetry.

pull_inventory.py writes valid Parquet locally without S3/Athena.

ETL produces nodes.jsonl/edges.jsonl that load into Neo4j with zero dangling references.

reachability_compare.py produces a diff report; PASS case matches AWS; FAIL case identifies the reason (ASYMMETRIC or BLACKHOLE).

All scripts run on macOS/Linux with just Python + Docker; no app deployment is required.

Instruction: Generate all code/files (Terraform, Python scripts, Makefile targets, README instructions, and example outputs) with concrete ARNs/IDs left as variables or examples. Keep costs minimal and ensure everything is read-only except the temporary Reachability Analyzer paths/analyses which are cleaned up.