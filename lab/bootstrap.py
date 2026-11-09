"""ubuntu-dev only: create an isolated bench/site using the existing Frappe runtime."""

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

BASE = Path("/home/vagrant/internal-vpn-lab")
SOURCE = Path(__file__).resolve().parents[1]
FRAPPE = Path("/home/vagrant/atlas-stack/bench/apps/frappe")


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


BASE.mkdir(mode=0o700, exist_ok=True)
for directory in ("apps", "sites", "logs", "config"):
    (BASE / directory).mkdir(exist_ok=True)
for name, source in (("frappe", FRAPPE), ("internal_vpn", SOURCE)):
    link = BASE / "apps" / name
    if not link.exists():
        link.symlink_to(source)
(BASE / "sites/apps.txt").write_text("frappe\ninternal_vpn\n")
common = {"redis_cache": "redis://127.0.0.1:16411", "redis_queue": "redis://127.0.0.1:16411",
          "redis_socketio": "redis://127.0.0.1:16411", "pause_scheduler": 1,
          "developer_mode": 0, "serve_default_site": True}
(BASE / "sites/common_site_config.json").write_text(json.dumps(common))
if not (BASE / "redis.pid").exists():
    run("redis-server", "--bind", "127.0.0.1", "--port", "16411", "--save", "", "--appendonly", "no",
        "--daemonize", "yes", "--pidfile", str(BASE / "redis.pid"), "--logfile", str(BASE / "logs/redis.log"))
sys.path[:0] = [str(SOURCE), str(FRAPPE)]
os.chdir(BASE / "sites")
import frappe

if not (BASE / "sites/test.local/site_config.json").exists():
    inspect = json.loads(run("sudo", "docker", "inspect", "atlas-stack-mariadb"))[0]
    environment = dict(item.split("=", 1) for item in inspect["Config"]["Env"] if "=" in item)
    password = environment.get("MARIADB_ROOT_PASSWORD") or environment["MYSQL_ROOT_PASSWORD"]
    import MySQLdb

    connection = MySQLdb.connect(host="127.0.0.1", port=13306, user="root", passwd=password)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='ivpn_poc'")
            if cursor.fetchone():
                raise RuntimeError("ivpn_poc already exists without this site's configuration; refusing to overwrite it")
    finally:
        connection.close()
    from frappe.installer import _new_site

    frappe.init("test.local", new_site=True)
    _new_site(db_name="ivpn_poc", site="test.local", db_root_username="root", db_root_password=password,
              admin_password=secrets.token_urlsafe(32), db_password=secrets.token_urlsafe(32),
              db_type="mariadb", db_host="127.0.0.1", db_port=13306,
              mariadb_user_host_login_scope="%", install_apps=["internal_vpn"])
    frappe.destroy()
    config = BASE / "sites/test.local/site_config.json"
    value = json.loads(config.read_text())
    value.update(allow_tests=True, pause_scheduler=True)
    config.write_text(json.dumps(value, indent=2))
    config.chmod(0o600)

frappe.init("test.local")
frappe.connect()
if frappe.conf.db_name != "ivpn_poc":
    raise RuntimeError("Refusing to install into another database")
from frappe.installer import install_app

for app in ("frappe", "internal_vpn"):
    if app not in frappe.get_installed_apps():
        install_app(app)
frappe.db.commit()
frappe.destroy()
config = BASE / "sites/test.local/site_config.json"
value = json.loads(config.read_text())
value.update(allow_tests=True, pause_scheduler=True)
config.write_text(json.dumps(value, indent=2))
config.chmod(0o600)

certificate = BASE / "config/server.crt"
key = BASE / "config/server.key"
if not certificate.exists():
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "14",
        "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=internal-vpn-lab",
        "-addext", "subjectAltName=IP:127.0.0.1")
    key.chmod(0o600)
print("Isolated VPN bench and test.local ready")
