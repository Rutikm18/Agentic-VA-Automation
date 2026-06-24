# ADVERSA Platform — Infrastructure Guide

## Architecture Overview

```
Internet → ALB → EKS (api ×3, worker ×2, agent-manager)
                     ↓ Kafka MSK
               enrichment-service → RDS PostgreSQL
               notification-service
               risk-scoring-service
                     ↓
               Neo4j (attack graph)
               ElastiCache Redis (jobs, sessions)
               S3 MinIO (evidence artifacts)
               HashiCorp Vault (secrets, mTLS certs)
```

---

## Local Dev Quickstart

### Prerequisites
- Docker Desktop 4.x+ with Compose v2
- `make` (optional)

### 1. Clone and configure

```bash
git clone https://github.com/adversa-io/adversa
cd adversa
cp infrastructure/.env.example infrastructure/.env
# Edit .env — set ANTHROPIC_API_KEY at minimum
```

### 2. Start the full stack

```bash
docker compose -f infrastructure/docker-compose.full.yml up -d

# Watch logs
docker compose -f infrastructure/docker-compose.full.yml logs -f api
```

### 3. Services

| Service       | URL                          | Credentials         |
|---------------|------------------------------|---------------------|
| ADVERSA UI    | http://localhost:3000         | —                   |
| Neo4j Browser | http://localhost:7474         | neo4j / changeme    |
| MinIO Console | http://localhost:9001         | minioadmin / ...    |
| Vault UI      | http://localhost:8200/ui      | Token: root-token   |

### 4. Stop / wipe

```bash
# Stop (keep data volumes)
docker compose -f infrastructure/docker-compose.full.yml down

# Full wipe including volumes
docker compose -f infrastructure/docker-compose.full.yml down -v
```

---

## Agent Deployment Guide

### Prerequisites on agent host
- Python 3.12+, nmap, nuclei
- Network access to platform API and HashiCorp Vault
- mTLS client certificate (issued at registration)

### 1. Register the agent

```bash
curl -X POST https://adversa.yourdomain.com/api/agents/register \
  -H "Content-Type: application/json" \
  -d '{
    "agentName": "corp-agent-03",
    "location": "On-Premise / CORP",
    "capabilities": ["discovery", "vuln_scan", "ad_enum"],
    "networkSegments": ["10.0.0.0/8"]
  }'
```

Response contains `tlsCert` and `vaultRoleToken`.

### 2. Store TLS cert

```bash
mkdir -p /etc/adversa/certs
echo "$TLS_CERT_RESPONSE" > /etc/adversa/certs/client.pem
echo "$TLS_KEY_RESPONSE"  > /etc/adversa/certs/client.key
chmod 600 /etc/adversa/certs/client.*
```

### 3. Run the agent

```bash
pip install -r infrastructure/agent/requirements.txt

AGENT_ID=AGT-XXX \
VAULT_ROLE_TOKEN=s.XXXXXXXXX \
PLATFORM_API_URL=https://adversa.yourdomain.com \
python3 infrastructure/agent/agent.py
```

### 4. Run via Docker

```bash
docker build -t adversa-agent infrastructure/agent/

docker run -d \
  --name adversa-agent-corp \
  -e AGENT_ID=AGT-XXX \
  -e PLATFORM_API_URL=https://adversa.yourdomain.com \
  -e VAULT_ROLE_TOKEN=s.XXXXXXXXX \
  -v /etc/adversa/certs:/etc/adversa/certs:ro \
  adversa-agent
```

### 5. Systemd unit (on-premise)

```ini
[Unit]
Description=ADVERSA Scanning Agent
After=network.target

[Service]
Type=simple
User=adversa-agent
EnvironmentFile=/etc/adversa/agent.env
ExecStart=/usr/bin/python3 /opt/adversa/agent/agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

---

## Kubernetes (Production)

### Prerequisites
- `kubectl` configured for target cluster
- `helm` 3.x
- Vault Agent Injector installed in cluster

### 1. Deploy

```bash
# Add any chart dependencies first
helm dependency update infrastructure/helm/adversa

# Dry run
helm upgrade --install adversa infrastructure/helm/adversa \
  --namespace adversa \
  --create-namespace \
  --values infrastructure/helm/adversa/values.yaml \
  --set ingress.host=adversa.yourdomain.com \
  --set api.image.tag=1.4.0 \
  --dry-run

# Deploy
helm upgrade --install adversa infrastructure/helm/adversa \
  --namespace adversa \
  --create-namespace \
  --values infrastructure/helm/adversa/values.yaml \
  --set ingress.host=adversa.yourdomain.com
```

### 2. Check rollout

```bash
kubectl rollout status deployment/adversa-api -n adversa
kubectl get pods -n adversa
kubectl get hpa -n adversa
```

---

## Terraform (AWS)

### Prerequisites
- AWS CLI configured with sufficient IAM permissions
- Terraform 1.7+
- S3 bucket + DynamoDB table for state (create once manually)

### 1. Init

```bash
cd infrastructure/terraform

terraform init \
  -backend-config="bucket=adversa-terraform-state" \
  -backend-config="region=us-east-1"
```

### 2. Plan

```bash
terraform plan \
  -var="db_password=$(openssl rand -base64 24)" \
  -out=tfplan
```

### 3. Apply

```bash
terraform apply tfplan
```

### Resources created
- VPC with 3 public + 3 private subnets across 3 AZs
- EKS cluster (managed node group, t3.xlarge, 3-12 nodes)
- RDS PostgreSQL 16 (db.t3.large, Multi-AZ, encrypted)
- ElastiCache Redis 7 (3-node cluster, encrypted in-transit)
- MSK Kafka 3.6 (3 brokers, TLS, min.insync.replicas=2)
- S3 bucket (versioned, KMS encrypted, public access blocked)
- IAM IRSA role for EKS → S3 access
- Secrets Manager secret for platform credentials

---

## Production Checklist

### Security
- [ ] Rotate VAULT_DEV_ROOT_TOKEN — use Vault HA with auto-unseal (AWS KMS)
- [ ] Enable mTLS for all agent ↔ platform communication
- [ ] Enable RDS encryption at rest (AWS KMS)
- [ ] Set `deletion_protection = true` on RDS
- [ ] Restrict Kubernetes API server access to VPN CIDR only
- [ ] Enable EKS audit logging to CloudWatch
- [ ] Rotate TLS certificates before expiry (365d)
- [ ] Enable GuardDuty on the AWS account

### Reliability
- [ ] Configure RDS read replica for reporting queries
- [ ] Set MSK `min.insync.replicas=2` and `acks=all` for producers
- [ ] Enable pod disruption budgets (minAvailable=2 for api)
- [ ] Test graceful agent shutdown under job load
- [ ] Verify HPA triggers correctly under load

### Observability
- [ ] Deploy Prometheus + Grafana (kube-prometheus-stack)
- [ ] Forward Kafka consumer lag metrics to Prometheus (JMX exporter)
- [ ] Configure CloudWatch alarms: RDS CPU >80%, Redis memory >85%
- [ ] Set up PagerDuty integration for critical alerts
- [ ] Enable distributed tracing (OpenTelemetry → Jaeger)
