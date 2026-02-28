# Kubepanel

Kubepanel is a free and open-source web hosting control panel based on Kubernetes (it supports microk8s out of the box at the moment).
The project is in an early PoC stage at the moment, the goal is to create an open source K8S based alternative to control panels like cPanel, DirectAdmin and others.
Since it's kubernetes native, the infrastructure is modular, you can add own container images to satisfy various customer needs.

# Prerequisites

- You need three Ubuntu 24.04 LTS servers with internet access 
- A public IP address and a DNS entry with an A record pointing to your public IP address. This is required to reach the Kubepanel UI after the installation. i.e.: if you have a domain name 'example.com' you can create an A record 'kubepanel.example.com' which resolves to your servers public IP address.
- For proper certificate management you can create a wildcard A record pointing to your public IP address(es). If wildcard is not an option, please make sure the following A records are pointing to at least one of your servers IP address: 'kubepanel.yourdomain.tld', 'webmail.kubepanel.yourdomain.tld', 'phpmyadmin.kubepanel.yourdomain.tld'.
- Open port 80, 443 on your firewall
- An empty disk attached under /dev/sdb
  
# INSTALL on the 1st node:

```
bash <(curl \
https://raw.githubusercontent.com/laszlokulcsar/kubepanel-infra/refs/heads/main/kubepanel-install.sh)
```
# INSTALL on the 2nd and 3rd node:

```
bash <(curl \
https://raw.githubusercontent.com/laszlokulcsar/kubepanel-infra/refs/heads/main/join-node.sh)
```

After the successful installation you can reach the Kubepanel UI on your choosen domain name.


# Features

- Django based web application for account management
- A hosting account uses Nginx and PHP containers by default
- Container images can be extended dynamically based on customer needs
- SFTP/SCP support (as sidecar container) for uploading codebase to the containers
- MariaDB as default database backend
- Postfix with DKIM signing for outgoing emails
- Automatic HTTPS certificate management by cert-manager
- Supports the latest Wordpress by default

# Mailbox management

- Mailbox management is natively supported now
- Roundcube is used as a Web UI
