# k8s-security-lab

Hands-on lab for container and Kubernetes security:
- Scan container images with Trivy
- Triage vulnerabilities with a small Python script
- Apply basic K8s hardening (non-root, RBAC, NetworkPolicy)
- Optional CI: run Trivy in GitHub Actions and publish a report artifact

## Quick Start (Local)
1) Install Trivy: https://aquasecurity.github.io/trivy/
2) Build a sample image:
3) Scan the image:
4) Triage findings (Python 3.10+):
5) Open `report.csv` in any viewer. It lists Sev/CVE/Package/FixedVersion.

## Kubernetes Hardening (AKS/EKS/Minikube/kind)
Apply the manifests in order:

What it shows:
- Namespaced RBAC + dedicated ServiceAccount
- NetworkPolicy (deny-by-default; allow DNS + in-namespace traffic)
- Pod securityContext (runAsNonRoot, readOnlyRootFilesystem, drop NET_RAW)

## CI (optional)
This repo includes `.github/workflows/trivy-ci.yml` to run Trivy on each push and upload a SARIF/JSON report as a build artifact.

## Notes
This is a learning repo. Use at your own risk; do not point scanners at production without approval.

