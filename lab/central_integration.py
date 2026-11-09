"""Attach a real Central HTTPS backend to a disposable VPN namespace via a Unix socket."""

import json
import os
from pathlib import Path
import subprocess
import time

BENCH = Path("/home/vagrant/central-rescue-3174d144")
PYTHON = "/home/vagrant/atlas-stack/bench/env/bin/python"


class CentralIntegration:
    def __init__(self, source, directory, run_id, namespace, address, run, check):
        self.source, self.directory, self.run_id = source, directory, run_id
        self.namespace, self.address, self.run, self.check = namespace, address, run, check
        self.processes = []
        self.fixture_path = directory / "central-fixture.json"
        self.environment = dict(os.environ, PYTHONPATH=f"{BENCH / 'apps/central'}:{source}",
                                SITES_PATH=str(BENCH / "sites"),
                                FRAPPE_REDIS_QUEUE=f"unix://{directory / 'central-redis.sock'}")

    def fixture_command(self, operation):
        result = subprocess.run([PYTHON, str(self.source / "lab/central_fixture.py"), operation,
                                 "--file", str(self.fixture_path), "--run-id", self.run_id],
                                env=self.environment, cwd=BENCH / "sites", capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError("Central fixture operation failed: " + result.stderr[-1800:])

    def start(self):
        redis_socket = self.directory / "central-redis.sock"
        redis = subprocess.Popen(["redis-server", "--port", "0", "--unixsocket", str(redis_socket),
                                  "--unixsocketperm", "700", "--save", "", "--appendonly", "no"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.processes.append(redis)
        for _ in range(40):
            if redis_socket.exists():
                break
            if redis.poll() is not None:
                raise RuntimeError("Isolated Central Redis exited")
            time.sleep(.1)
        self.fixture_command("create")
        self.fixture = json.loads(self.fixture_path.read_text())
        self.certificate = self.directory / "central.crt"
        key = self.directory / "central.key"
        self.run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-keyout", str(key), "-out", str(self.certificate), "-subj", "/CN=central.poc.test",
                 "-addext", "subjectAltName=DNS:central.poc.test")
        key.chmod(0o600)
        socket = self.directory / "central.sock"
        self.log = (self.directory / "central-server.log").open("w")
        server = subprocess.Popen([PYTHON, "-m", "gunicorn", "--workers", "1", "--bind", f"unix:{socket}",
                                   "--certfile", str(self.certificate), "--keyfile", str(key),
                                   "lab.central_wsgi:application"], cwd=BENCH / "sites", env=self.environment,
                                  stdout=self.log, stderr=self.log, start_new_session=True)
        self.processes.append(server)
        for _ in range(40):
            if socket.exists():
                break
            if server.poll() is not None:
                raise RuntimeError("Central test server failed: " + (self.directory / "central-server.log").read_text()[-1800:])
            time.sleep(.1)
        # Relay TLS bytes unchanged. Central terminates TLS and enforces its own permissions.
        for prefix, listener in (
            (["sudo", "ip", "netns", "exec", self.namespace, "runuser", "-u", "vagrant", "--"],
             f"TCP4-LISTEN:8443,bind={self.address},reuseaddr,fork"),
            ([], "TCP4-LISTEN:18442,bind=127.0.0.1,reuseaddr,fork"),
        ):
            self.processes.append(subprocess.Popen([*prefix, "socat", listener, f"UNIX-CONNECT:{socket}"],
                                                   stdout=self.log, stderr=self.log, start_new_session=True))
        time.sleep(.3)
        return self

    def request(self, path, token=None, namespace=None, data=None, headers=None):
        host, port = (self.address, 8443) if namespace else ("127.0.0.1", 18442)
        # Keep the credential out of process arguments. curl reads it from stdin.
        config = 'silent\nshow-error\nnoproxy = "*"\nmax-time = 4\n'
        if token:
            config += f'header = "Authorization: token {token}"\n'
        for key, value in (headers or {}).items():
            config += f'header = "{key}: {value}"\n'
        arguments = ["curl", "--config", "-", "--cacert", str(self.certificate),
                     "--connect-to", f"central.poc.test:443:{host}:{port}", "-w", "\n%{http_code}"]
        if data is not None:
            arguments += ["-H", "Content-Type: application/json", "--data", json.dumps(data)]
        arguments.append("https://central.poc.test" + path)
        if namespace:
            arguments = ["sudo", "ip", "netns", "exec", namespace, *arguments]
        response = self.run(*arguments, input=config, check=False)
        if response.returncode:
            return 0, {}
        body, status = response.stdout.rsplit("\n", 1)
        try:
            value = json.loads(body)
        except ValueError:
            value = {}
        return int(status), value

    def verify(self, engineer_namespace, service_namespace, vpn_token):
        customer, operator = self.fixture["customer"], self.fixture["operator"]
        profile = "/api/method/central.api.identity.my_profile"
        status, body = self.request(profile, customer["token"], engineer_namespace)
        self.check("central_customer_profile_over_wireguard", status == 200 and body["message"]["user"] == customer["user"])
        self.check("central_requires_app_auth_over_vpn", self.request(profile, namespace=engineer_namespace)[0] in (401, 403))
        self.check("vpn_control_plane_token_not_a_central_credential", self.request(profile, vpn_token, engineer_namespace)[0] in (401, 403))
        admin = "/api/resource/System%20Settings/System%20Settings"
        self.check("central_customer_cannot_read_system_settings_over_vpn", self.request(admin, customer["token"], engineer_namespace)[0] == 403)
        self.check("central_operator_can_read_system_settings_over_vpn", self.request(admin, operator["token"], engineer_namespace)[0] == 200)
        self.check("central_service_peer_can_make_authenticated_request", self.request(profile, customer["token"], service_namespace)[0] == 200)
        self.check("central_customer_api_still_works_without_vpn", self.request(profile, customer["token"])[0] == 200)
        self.check("central_public_guest_auth_validation_preserved", self.request(
            "/api/method/central.api.auth.send_code", data={"email": "invalid-email"})[0] == 417)
        # This is evidence of an unmet requirement, not an access-control acceptance pass.
        self.check("central_baseline_exposes_admin_api_without_vpn", self.request(admin, operator["token"])[0] == 200)
        self.check("forwarded_address_does_not_grant_central_role", self.request(
            admin, customer["token"], headers={"X-Forwarded-For": "100.100.64.3"})[0] == 403)
        status, body = self.request("/api/method/central.api.identity.my_capabilities", customer["token"], engineer_namespace)
        self.check("vpn_does_not_grant_central_capabilities", status == 200 and body["message"] == [])
        status, body = self.request("/api/method/central.api.identity.my_teams", customer["token"], engineer_namespace)
        self.check("vpn_does_not_grant_central_team_membership", status == 200 and body["message"] == [])

    def verify_revocation(self, engineer_namespace, service_namespace):
        profile = "/api/method/central.api.identity.my_profile"
        token = self.fixture["customer"]["token"]
        self.check("vpn_revocation_blocks_real_central_connection", self.request(profile, token, engineer_namespace)[0] == 0)
        self.check("service_access_to_central_survives_device_revocation", self.request(profile, token, service_namespace)[0] == 200)

    def close(self):
        try:
            self.fixture_command("remove")
        finally:
            for process in reversed(self.processes):
                self.run("sudo", "kill", "--", f"-{process.pid}", check=False)
                if process.poll() is None:
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self.run("sudo", "kill", "-KILL", "--", f"-{process.pid}", check=False)
                        process.wait()
            if hasattr(self, "log"):
                self.log.close()
