# 🛡️ CaTO DevSecOps Pipeline

A fully automated, CaTO-compliant DevSecOps pipeline built using **GitHub Actions**, **Syft**, **Grype**, and **OPA**.

This project continuously scans containerized applications for vulnerabilities, generates SBOMs, enforces security policies, and pushes compliance reports into the repository — simulating a **Continuous Authority to Operate (CaTO)** pipeline used in government and defense environments.

---

## 🚀 Features

✅ Docker container build  
✅ Software Bill of Materials (SBOM) generation with **Syft**  
✅ Vulnerability scanning with **Grype**  
✅ Custom policy enforcement using **OPA** (Rego)  
✅ Compliance report written to `reports/report.md`  
✅ GitHub Actions CI/CD pipeline  
✅ Auto-push reports back to the repo  

---

## 🧱 Pipeline Overview

```mermaid
graph TD
  A[Code Commit] --> B[Build Docker Image]
  B --> C[Generate SBOM with Syft]
  B --> D[Run CVE Scan with Grype]
  C --> E[Evaluate Policies with OPA]
  D --> E
  E --> F[Write Compliance Report]
  F --> G[Commit & Push to Repo]

