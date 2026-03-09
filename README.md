# KubePanel

**Kubernetes-native web hosting control panel — a self-hosted alternative to cPanel and DirectAdmin.**

[![License: KubePanel SAL v1.0](https://img.shields.io/badge/license-KubePanel%20SAL%20v1.0-blue)](./LICENSE)
[![Kubernetes](https://img.shields.io/badge/kubernetes-microk8s-326CE5?logo=kubernetes)](https://microk8s.io)
[![Python](https://img.shields.io/badge/python-3.12-3776AB?logo=python)](https://www.python.org)

---

## What is KubePanel?

KubePanel is a Kubernetes-native web hosting control panel designed as a modern replacement for cPanel, DirectAdmin, and Plesk. It runs on your own infrastructure — three Ubuntu servers are all you need — and uses Kubernetes to deliver high availability, self-healing, and multi-workload hosting out of the box.

Each hosting account runs in its own isolated Kubernetes namespace with dedicated containers for the web application, Nginx, SFTP, and email. Infrastructure is managed by a Kubernetes operator, so provisioning, scaling, and failure recovery happen automatically without manual intervention.

---

## Features

**Workloads & Web**
- Multi-workload support: PHP, Python, Node.js, and Django — admin-configurable runtimes and versions
- Nginx reverse proxy per domain with automatic SSL certificates (cert-manager + Let's Encrypt)
- WordPress one-click pre-installation
- Domain suspension and unsuspension

**Access & Storage**
- SFTP/SCP access per hosting account (sidecar container, NodePort)
- MariaDB database and user provisioned automatically per domain

**Email**
- Outgoing email with Postfix and per-domain DKIM signing (OpenDKIM)
- Mailbox management with Roundcube webmail

**Security**
- Per-domain and global WAF rules
- Country-based IP blocking (GeoIP)
- Container-level workload isolation

**DNS**
- Cloudflare DNS zone management

**Infrastructure**
- Kubernetes operator (kopf) for continuous reconciliation and self-healing
- High availability via microk8s multi-node cluster
- Linstor storage with automatic PVC provisioning

---

## Architecture

```
Django Dashboard          (business logic: accounts, packages, DNS, email)
       │
       │  Creates/Updates Domain Custom Resources
       ▼
Kubernetes Domain CR      (spec: workload type, resources, email, SSL config)
       │
       │  Watches & Reconciles
       ▼
Kopf Operator             (provisions all K8s resources, manages secrets,
       │                   configures DKIM, self-heals on drift)
       │
       ▼
Per-Domain Namespace
  ├── Deployment (app + nginx + sftp containers)
  ├── PersistentVolumeClaim
  ├── Secrets (SFTP credentials, DB credentials, DKIM keys)
  ├── ConfigMap (nginx config)
  ├── Service (ClusterIP + NodePort for SFTP)
  └── Ingress (TLS via cert-manager)
```

---

## Supported Workloads

| Type    | Default Port | Proxy Mode | Use Case             |
|---------|-------------|------------|----------------------|
| PHP     | 9001        | FastCGI    | PHP-FPM applications |
| Python  | 8000        | HTTP       | Gunicorn / WSGI apps |
| Node.js | 3000        | HTTP       | Express / Node apps  |
| Django  | 8000        | HTTP       | Django applications  |

Workload types and container images are managed through the Django admin — no code changes required to add new runtimes.

---

## Requirements

- **3 × Ubuntu 24.04 LTS servers** with internet access
- A **public IP address** and a DNS A record pointing to it (e.g. `kubepanel.yourdomain.tld`)
- For full certificate management: a wildcard A record, or individual A records for `kubepanel.yourdomain.tld`, `webmail.kubepanel.yourdomain.tld`, and `phpmyadmin.kubepanel.yourdomain.tld`
- **Open ports:** 80, 443 (and NodePort range for SFTP)
- An **empty disk attached at `/dev/sdb`** on each node (used for Linstor storage)

---

## Installation

**First node:**

```bash
bash <(curl https://raw.githubusercontent.com/kubepanel-io/kubepanel-infra/refs/heads/main/kubepanel-install.sh)
```

**Second and third nodes:**

```bash
bash <(curl https://raw.githubusercontent.com/kubepanel-io/kubepanel-infra/refs/heads/main/join-node.sh)
```

After a successful installation, KubePanel is accessible at the domain you configured during setup.

---

## Managed Cloud

Don't want to manage the infrastructure yourself? KubePanel is available as a fully managed cloud service. We provision a dedicated 3-node Kubernetes cluster on your behalf and keep it running — you receive a dashboard URL and admin credentials, ready to go.

Available in EU and US regions. Plans start at $89/month.

**[View managed plans at kubepanel.io/pricing](https://kubepanel.io/pricing)**

---

## License

KubePanel is **source-available** under the [KubePanel Source-Available License v1.0](./LICENSE).

| Use case | License required |
|----------|-----------------|
| Inspect and modify the source code | Free, no key needed |
| Run KubePanel managing **up to 5 domains** (Community tier) | Free, no key needed |
| Run KubePanel managing **6+ domains** (Commercial use) | Paid license key required |

Paid licenses are available at **[kubepanel.io/pricing](https://kubepanel.io/pricing)**.

> This is not an OSI-approved open-source license. If your paid license expires, existing hosted sites continue running — only creation of new domains beyond the free tier limit is restricted.

---

## Contributing

Pull requests are welcome. By submitting a contribution, you agree that your code will be licensed under the same [KubePanel Source-Available License v1.0](./LICENSE), including its copyleft and source-disclosure requirements.

Please open an issue first for significant changes to discuss the approach before investing time in implementation.

---

## Links

- **Website:** [kubepanel.io](https://kubepanel.io)
- **Pricing:** [kubepanel.io/pricing](https://kubepanel.io/pricing)
- **Issues:** [GitHub Issues](https://github.com/kubepanel-io/kubepanel/issues)
- **License:** [LICENSE](./LICENSE)
- **Contact:** licensing@kubepanel.io
