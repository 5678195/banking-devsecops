# 🔐 Secure Banking API Platform with DevSecOps Pipeline

A production-grade DevSecOps project simulating a real-world fintech banking platform.

## 🏗️ Architecture
Developer → GitHub Actions → SonarQube → Trivy → Docker → Terraform → Kubernetes → Prometheus/Grafana

## 🛠️ Tech Stack
- **Backend:** FastAPI (Python) + JWT Authentication
- **Security:** Trivy (vulnerability scanning), SonarQube (code quality)
- **Infrastructure:** Terraform (AWS VPC, Subnet), AWS Secrets Manager
- **Container Orchestration:** Kubernetes (K3s) with 2 replicas
- **Monitoring:** Prometheus + Grafana (CPU, Memory, Disk dashboards)
- **CI/CD:** GitHub Actions (automated pipeline)

## 🚀 Features
- JWT Login/Register API
- Automated security scanning on every push
- Infrastructure as Code with Terraform
- Secrets management with AWS Secrets Manager
- Kubernetes deployment with auto-healing
- Real-time monitoring dashboards

## 📊 Live Monitoring
- Grafana Dashboard: CPU, Memory, Disk metrics
- Prometheus: Metrics collection every 15s

## 🔒 Security
- Docker image vulnerability scanning (Trivy)
- Code quality gates (SonarQube)
- Secrets stored in AWS Secrets Manager (not in code)
