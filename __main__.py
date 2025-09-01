import hashlib
from pathlib import Path
import pulumi
from pulumi import Config, ResourceOptions
from pulumi_command import remote

cfg = Config()
host = cfg.require("host")
ssh_user = cfg.get("sshUser") or "ubuntu"
ssh_private_key = cfg.require("sshPrivateKey")
domain = cfg.require("domain")
email = cfg.require("email")
cert_mode = (cfg.get("certMode") or "traefik").lower()
stack_name = cfg.get("stackName") or "mystack"
remote_compose_path = cfg.get("remoteComposePath") or f"/opt/stacks/{stack_name}/docker-compose.yml"
acme_staging = cfg.get_bool("acmeStaging") or False

compose_bytes = Path("docker-compose.yml").read_bytes()
compose_sha256 = hashlib.sha256(compose_bytes).hexdigest()

conn = remote.ConnectionArgs(
    host=host,
    user=ssh_user,
    private_key=ssh_private_key,
    port=22,
)

ensure_dirs = remote.Command(
    "ensure-dirs",
    connection=conn,
    create=" && ".join([
        f"sudo mkdir -p \"$(dirname {remote_compose_path})\"",
        "sudo mkdir -p /opt/certbot/etc /opt/certbot/var",
        "sudo mkdir -p /opt/traefik /opt/bin",
    ]),
)

install_basics = remote.Command(
    "install-basics",
    connection=conn,
    create=" && ".join([
        "if ! command -v curl >/dev/null 2>&1; then sudo apt-get update -y && sudo apt-get install -y curl; fi",
        "if ! command -v cron >/dev/null 2>&1; then sudo apt-get update -y && sudo apt-get install -y cron; fi",
    ]),
    opts=ResourceOptions(depends_on=[ensure_dirs]),
)

install_docker = remote.Command(
    "install-docker",
    connection=conn,
    create=" && ".join([
        "if ! command -v docker >/dev/null 2>&1; then curl -fsSL https://get.docker.com | sudo sh; fi",
        "sudo systemctl enable docker",
        "sudo systemctl restart docker",
        f"sudo usermod -aG docker {ssh_user} || true",
    ]),
    opts=ResourceOptions(depends_on=[install_basics]),
)

swarm_init = remote.Command(
    "swarm-init",
    connection=conn,
    create=r"""
if ! sudo docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null | grep -qiE 'active|pending'; then
  ADVIP=$(hostname -I | awk '{print $1}')
  sudo docker swarm init --advertise-addr "$ADVIP"
fi
""".strip(),
    opts=ResourceOptions(depends_on=[install_docker]),
)

upload_compose = remote.CopyFile(
    "upload-compose",
    connection=conn,
    local_path="docker-compose.yml",
    remote_path=remote_compose_path,
    opts=ResourceOptions(depends_on=[ensure_dirs]),
)

if cert_mode == "certbot":
    cert_step = remote.Command(
        "certbot-bootstrap",
        connection=conn,
        create=f"""
set -e
if [ ! -f /opt/certbot/etc/live/{domain}/privkey.pem ]; then
  sudo docker run --rm -p 80:80 -p 443:443 \
    -v /opt/certbot/etc:/etc/letsencrypt \
    -v /opt/certbot/var:/var/lib/letsencrypt \
    certbot/certbot certonly --standalone \
      -d {domain} -m {email} --agree-tos --no-eff-email --non-interactive
fi
sudo bash -c 'cat >/etc/cron.d/certbot-renew' <<'CRON'
0 3 * * * root /usr/bin/docker run --rm \
  -v /opt/certbot/etc:/etc/letsencrypt \
  -v /opt/certbot/var:/var/lib/letsencrypt \
  certbot/certbot renew --quiet
CRON
sudo chmod 644 /etc/cron.d/certbot-renew
""",
        opts=ResourceOptions(depends_on=[swarm_init]),
    )
else:
    staging_flag = "--certificatesresolvers.le.acme.caserver=https://acme-staging-v02.api.letsencrypt.org/directory" if acme_staging else "true"
    cert_step = remote.Command(
        "traefik-acme-prepare",
        connection=conn,
        create=" && ".join([
            "sudo mkdir -p /opt/traefik",
            "sudo touch /opt/traefik/acme.json",
            "sudo chmod 600 /opt/traefik/acme.json",
            f"echo {staging_flag} >/tmp/traefik-acme-mode",
        ]),
        opts=ResourceOptions(depends_on=[swarm_init]),
    )

deploy_stack = remote.Command(
    "stack-deploy",
    connection=conn,
    create=f"cd \"$(dirname {remote_compose_path})\" && sudo docker stack deploy -c {remote_compose_path} {stack_name}",
    update=f"cd \"$(dirname {remote_compose_path})\" && sudo docker stack deploy -c {remote_compose_path} {stack_name}",
    triggers=[compose_sha256, cert_mode, domain, email],
    opts=ResourceOptions(depends_on=[upload_compose, cert_step]),
)

pulumi.export("server", host)
pulumi.export("swarm", "initialized")
pulumi.export("stack", stack_name)
pulumi.export("compose", remote_compose_path)
pulumi.export("certs", cert_mode)
