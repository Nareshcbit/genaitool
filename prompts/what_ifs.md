1. Networking & Connectivity

Cross-VPC reachability: Already built (ENI→ENI, TGW, Peering, VPN, DX).

Internet exposure drift: What if I add this SG rule — does it make a private subnet reachable from the internet?

TGW/Peering blast radius: What if we attach VPC-X to TGW-Y — which VPCs suddenly become reachable?

DNS reachability: What if I flip Private Hosted Zone association — which services lose/gain name resolution?

Route table change: What if I add a 0.0.0.0/0 route to a NAT GW — which workloads now have outbound internet access?

2. Security & DevSecOps

IAM what-if:

What if I attach this policy — can it escalate to admin?

What if I allow s3:* — which buckets become writable?

KMS key trust:

What if I grant this role key decrypt — which workloads can now read sensitive data?

S3 bucket policy:

What if I add a cross-account principal — which accounts gain access?

Public ECR images:

What if I reference this base image — does it comply with org policy (signed/approved)?

Security group changes:

What if I widen ingress to 0.0.0.0/0 — what assets are now exposed?

GuardDuty suppression:

What if I suppress this finding type — will we miss real threats?

3. SRE & Ops

High-availability what-if:

What if AZ-1 fails — which services lose quorum?

What if a NAT Gateway in one AZ is removed — does egress still work for all subnets?

Scaling & limits:

What if traffic spikes 10× — do ASGs/EKS nodes scale before API rate limits hit?

What if we cross service quotas (ENIs per AZ, TGW route table entries)?

Chaos test planning:

What if I kill all EC2s in subnet-B — does the ALB still pass health checks?

Operational dependency graph:

What if CloudWatch Logs is throttled — which pipelines and apps silently fail?

4. Cloud Platform / Governance

Cost what-if:

What if I enable VPC Flow Logs on all VPCs — how much will it cost?

What if I turn on GuardDuty org-wide — monthly delta?

Region migration:

What if we move this workload to eu-west-1 — are all services (KMS, RDS, Lambda layers) available?

Org SCP change:

What if I deny ec2:CreateVpcPeeringConnection — which teams’ IaC will fail?

Centralization:

What if we centralize NAT GWs — which teams’ egress patterns break?

5. GIS / Geo-Aware Teams

Data residency:

What if I enable cross-region replication to us-east-1 — does it break GDPR?

Edge latency:

What if CloudFront POP in India goes down — what is latency impact for APAC users?

Route 53 traffic policy:

What if I change weighted routing from 50/50 to 100/0 — how does it shift user traffic maps?

GeoIP firewall rules:

What if I block all of China in WAF — which user base % is denied?

6. Application & Dev Teams

EKS what-if:

What if I change endpointPublicAccess=true — do devs gain/loss cluster access?

What if I upgrade EKS 1.24→1.29 — which API versions/CRDs break?

RDS/DB what-if:

What if I flip from Single-AZ to Multi-AZ — downtime?

What if I enable global database — replication lag + failover paths?

Lambda execution env:

What if I attach this VPC config — do cold starts increase due to ENI attach?

Queue/topic:

What if I widen SNS topic policy — which accounts can publish?

Secrets Manager:

What if I rotate this secret — which Lambda/ECS tasks break?

🛠️ How to Make These Work in Your Tool

Input normalization:

Already have nodes/edges; add tags, accounts, regions, compliance metadata as node props.

This powers policy checks (prod→dev, PCI workloads, etc.).

Scenario templates:

Define YAML “what-if packs” for each domain. Example:

- id: s3-public-policy
  question: "What if bucket policy allows *:s3:GetObject from *?"
  check: s3PolicyAnalyzer
  risk: "Public data exposure"


Each pack maps to a handler (graph query, IAM analyzer, or LLM reasoning).

Execution engine:

For each what-if, extract relevant subgraph → feed to Bedrock + deterministic checker.

Return decision, evidence, riskLevel.

Consumption surfaces:

Pre-merge checks in Terraform CI/CD.

On-demand queries via CLI/API.

Scheduled compliance sweeps (nightly drift detection).

Portal dashboards (policy violations, cost diffs, geo impact maps).

✅ Immediate Next Steps

Pick 2–3 what-if scenarios per persona (Networking, Security, DevOps).

Implement as YAML rules + graph queries → call your Bedrock reachability/explainer.

Add to CLI:

reach what-if s3-public-policy --bucket my-data
reach what-if tgw-attach --src-vpc vpc-a --dst-vpc vpc-b
reach what-if eks-public-access --cluster dev-cluster


Demo to Platform team: “Here are the top 5 what-if questions we can answer today.”