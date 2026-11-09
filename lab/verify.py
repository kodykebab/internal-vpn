"""Real Frappe HTTPS API + root updater + disposable kernel WireGuard peers.

Run as vagrant with the Atlas bench Python after lab/bootstrap.py. No production sites.
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

BASE = Path("/home/vagrant/internal-vpn-lab")
SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
from internal_vpn.host import accept_revision, validate_snapshot

results = {}
processes = []
namespaces = []
users = []
peer_names = []
central = None
url = "https://127.0.0.1:18441"
ca_file = str(BASE / "config/server.crt")
run_id = secrets.token_hex(4)
host_root = Path("/run") / ("internal-vpn-poc-" + run_id)
namespace_names = [f"ivpn-poc-{run_id}-{i}" for i in range(4)]


def run(*args, check=True, input=None):
    result = subprocess.run(args, check=check, input=input, text=True, capture_output=True, timeout=30)
    return result


def check(name, passed):
    results[name] = bool(passed)
    print(json.dumps({name: bool(passed)}), flush=True)
    if not passed:
        raise AssertionError(name)


def request(path, token=None, data=None, method=None, extra_headers=None):
    context = ssl.create_default_context(cafile=ca_file)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers.update(extra_headers or {})
    if token:
        headers["Authorization"] = "token " + token
    req = Request(url + path, headers=headers, data=json.dumps(data).encode() if data is not None else None,
                  method=method)
    try:
        with opener.open(req, timeout=15) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except HTTPError as error:
        try:
            body = json.loads(error.read())
        except (ValueError, UnicodeError):
            body = {}
        return error.code, {key: body[key] for key in ("exc_type", "exception") if key in body}


def api(method, token, data=None, get=False):
    path = "/api/method/internal_vpn.api." + method
    if get:
        path += "?" + urlencode(data or {})
    for attempt in range(6):
        status, body = request(path, token, None if get else data)
        if status != 508 or body.get("exc_type") != "QueryDeadlockError":
            break
        # Frappe rolls back this transaction; retry only this explicit conflict response.
        print(json.dumps({"retry_after_transaction_conflict": method}), flush=True)
        time.sleep(.05 * (attempt + 1))
    if status != 200:
        raise RuntimeError(f"API {method} failed with HTTP {status}: {body}")
    return body["message"]


def create_user(tag, roles):
    import frappe

    email = f"ivpn-{run_id}-{tag}@example.invalid"
    user = frappe.get_doc(dict(doctype="User", email=email, first_name=tag, send_welcome_email=0,
                              user_type="System User", roles=[dict(role=r) for r in roles]))
    user.insert(ignore_permissions=True)
    users.append(email)
    api_key, secret = secrets.token_hex(10), secrets.token_hex(24)
    user.api_key, user.api_secret = api_key, secret
    user.save(ignore_permissions=True)
    return email, f"{api_key}:{secret}"


def net(index, *args, check=True):
    return run("sudo", "ip", "netns", "exec", namespace_names[index], *args, check=check)


def ping(source, address):
    return net(source, "ping", "-c", "1", "-W", "1", address, check=False).returncode == 0


@contextmanager
def lab_directory():
    with tempfile.TemporaryDirectory(prefix="ivpn-poc-") as temporary:
        try:
            yield temporary
        finally:
            if central:
                try:
                    central.close()
                    results["central_fixture_removed"] = True
                except Exception as error:
                    results["central_fixture_removed"] = False
                    print("Central cleanup failed: " + type(error).__name__, flush=True)
            run("sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", temporary)


try:
    if os.geteuid() == 0:
        raise RuntimeError("Run the Frappe lab as vagrant, not root")
    os.chdir(BASE / "sites")
    import frappe

    frappe.init("test.local")
    frappe.connect()
    if frappe.conf.db_name != "ivpn_poc":
        raise RuntimeError("Refusing to test another database")
    manager, manager_token = create_user("manager", ["VPN Manager", "System Manager"])
    engineer, engineer_token = create_user("engineer", ["VPN Engineer"])
    other_engineer, other_engineer_token = create_user("other-engineer", ["VPN Engineer"])
    outsider, outsider_token = create_user("outsider", [])
    hosts = [create_user(f"service{i}", ["VPN Host"]) for i in range(2)]
    frappe.db.commit()
    frappe.destroy()

    with lab_directory() as temporary:
        directory = Path(temporary)
        run("sudo", "install", "-d", "-m", "0700", str(host_root), str(host_root / "internal_vpn"))
        for file in ("host.py", "validation.py", "__init__.py"):
            run("sudo", "install", "-m", "0644", str(SOURCE / "internal_vpn" / file), str(host_root / "internal_vpn" / file))
        run("sudo", "install", "-m", "0644", str(SOURCE / "run-host.py"), str(host_root / "run-host.py"))
        environment = dict(os.environ, PYTHONPATH=str(SOURCE), SITES_PATH=str(BASE / "sites"), VPN_SITE="test.local")
        log = (BASE / "logs/poc-http.log").open("w")
        server = subprocess.Popen([sys.executable, "-m", "gunicorn", "--workers", "2", "--bind", "127.0.0.1:18441",
                                   "--certfile", ca_file, "--keyfile", str(BASE / "config/server.key"),
                                   "internal_vpn.wsgi:application"], env=environment, stdout=log, stderr=log)
        processes.append(server)
        for attempt in range(40):
            try:
                status, _ = request("/api/method/internal_vpn.api.status")
                if status in (401, 403):
                    break
            except (URLError, ConnectionError):
                pass
            if server.poll() is not None:
                raise RuntimeError("PoC HTTPS server exited; inspect local log")
            time.sleep(.5)
        check("frappe_runs_without_root", os.geteuid() != 0 and server.poll() is None)
        check("anonymous_api_denied", request("/api/method/internal_vpn.api.status")[0] in (401, 403))
        check("anonymous_desk_denied", request("/desk")[0] in (401, 403))
        check("login_exception_cannot_dispatch_guest_method", request("/login?cmd=frappe.ping")[0] in (401, 403))
        check("anonymous_generic_resource_denied", request("/api/resource/User")[0] in (401, 403))
        check("socket_polling_denied", request("/socket.io/?EIO=4&transport=polling")[0] == 403)
        check("socket_upgrade_denied", request("/socket.io/?EIO=4&transport=websocket", extra_headers={
              "Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
              "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="})[0] == 403)
        check("nonmember_cannot_register", request("/api/method/internal_vpn.api.register", outsider_token,
              dict(kind="Device", public_key="invalid"))[0] == 403)
        check("engineer_cannot_register_service", request("/api/method/internal_vpn.api.register", engineer_token,
              dict(kind="Service", public_key="invalid"))[0] == 403)
        check("empty_network_not_reported_ready", not api("status", manager_token, get=True)["all_current"])
        api("initialize", manager_token, {"subnet": "100.100.64.0/24"})

        public_keys, configs, addresses = [], [], []
        for index in range(4):
            private = run("wg", "genkey").stdout.strip()
            public = run("wg", "pubkey", input=private).stdout.strip()
            public_keys.append(public)
            keyfile = directory / f"key{index}"
            keyfile.write_text(private)
            keyfile.chmod(0o600)
            if index < 2:
                record = api("register", manager_token, dict(kind="Service", public_key=public, user=hosts[index][0],
                             endpoint=f"127.0.0.1:{56441 + index}"))
            elif index == 2:
                record = api("register", engineer_token, dict(kind="Device", public_key=public))
            else:
                record = {"name": "unregistered", "address": "100.100.64.254"}
            if index < 3:
                peer_names.append(record["name"])
            addresses.append(record["address"])
            name = namespace_names[index]
            run("sudo", "ip", "netns", "add", name)
            namespaces.append(name)
            interface = f"iv{run_id}{index}"
            run("sudo", "ip", "link", "add", interface, "type", "wireguard")
            run("sudo", "ip", "link", "set", interface, "netns", name)
            run("sudo", "ip", "-n", name, "link", "set", interface, "name", "ivpn0")
            net(index, "wg", "set", "ivpn0", "private-key", str(keyfile), "listen-port", str(56441 + index))
            run("sudo", "ip", "-n", name, "address", "add", record["address"] + "/24", "dev", "ivpn0")
            run("sudo", "ip", "-n", name, "link", "set", "lo", "up")
            run("sudo", "ip", "-n", name, "link", "set", "ivpn0", "up")
            config = dict(name=record["name"], address=record["address"], public_key=public,
                          subnet="100.100.64.0/24", interface="ivpn0", namespace=name,
                          url=url, ca_file=ca_file, token=hosts[index][1] if index < 2 else engineer_token)
            configs.append(config)
            if index < 2:
                path = directory / f"host{index}.json"
                path.write_text(json.dumps(config))
                path.chmod(0o600)
                run("sudo", "install", "-m", "0600", str(path), str(host_root / f"host{index}.json"))
                path.unlink()

        def update(index, expect=True):
            result = run("sudo", "python3", str(host_root / "run-host.py"), "--config", str(host_root / f"host{index}.json"),
                         "--state", str(host_root / f"state{index}"), check=False)
            if expect and result.returncode != 0:
                raise RuntimeError(f"Host {index} updater failed")
            return result.returncode == 0

        def configure_client(index=2, reconnect=False):
            # Engineer owns the private key and applies public configuration locally.
            data = api("configuration", engineer_token, {"name": peer_names[2]}, get=True)
            for peer in data["peers"]:
                if peer["endpoint"]:
                    if reconnect:
                        net(index, "wg", "set", "ivpn0", "peer", peer["public_key"], "remove")
                    net(index, "wg", "set", "ivpn0", "peer", peer["public_key"], "allowed-ips", peer["address"] + "/32",
                        "endpoint", peer["endpoint"], "persistent-keepalive", "25")
            return data

        check("host_cannot_fetch_another_host", request("/api/method/internal_vpn.api.configuration?" +
              urlencode({"name": peer_names[1]}), hosts[0][1])[0] == 403)
        check("host_cannot_change_membership", request("/api/method/internal_vpn.api.update_peer", hosts[0][1],
              {"name": peer_names[2], "enabled": 0})[0] == 403)
        check("generic_doctype_write_denied", request("/api/resource/VPN%20Peer/" + peer_names[2], manager_token,
              {"address": "100.100.64.99"}, method="PUT")[0] == 403)
        check("duplicate_key_rejected", request("/api/method/internal_vpn.api.register", engineer_token,
              {"kind": "Device", "public_key": public_keys[2]})[0] in (409, 417))
        from lab.review_checks import verify_inputs

        verify_inputs(api, request, check, manager_token, engineer_token, other_engineer_token,
                      outsider_token, hosts[0][1], peer_names)
        revision = api("status", manager_token, get=True)["revision"]
        check("profile_edit_succeeds", request("/api/resource/User/" + engineer, manager_token,
              {"first_name": "Updated engineer"}, method="PUT")[0] == 200)
        check("profile_edit_does_not_invalidate_host_reports", api("status", manager_token, get=True)["revision"] == revision)
        check("engineer_credential_survives_profile_edit", request("/api/method/internal_vpn.api.configuration?" +
              urlencode({"name": peer_names[2]}), engineer_token)[0] == 200)
        def enroll_extra(_):
            private = run("wg", "genkey").stdout.strip()
            public = run("wg", "pubkey", input=private).stdout.strip()
            return api("register", engineer_token, {"kind": "Device", "public_key": public})
        with ThreadPoolExecutor(max_workers=4) as pool:
            concurrent = list(pool.map(enroll_extra, range(4)))
        check("concurrent_enrollment_allocates_unique_addresses_and_revisions",
              len({item["address"] for item in concurrent}) == 4 and len({item["revision"] for item in concurrent}) == 4)
        for item in concurrent:
            api("update_peer", engineer_token, {"name": item["name"], "enabled": 0})
        update(0)
        update(1)
        configure_client()
        check("direct_service_connectivity", ping(0, addresses[1]) and ping(1, addresses[0]))
        check("engineer_reaches_both_services", ping(2, addresses[0]) and ping(2, addresses[1]))
        check("applied_revision_reported", api("status", manager_token, get=True)["all_current"])
        denied = net(0, "runuser", "-u", "vagrant", "--", "wg", "set", "ivpn0", "listen-port", "56441", check=False)
        check("app_user_cannot_modify_wireguard", denied.returncode != 0 and "Operation not permitted" in denied.stderr)
        with ThreadPoolExecutor(max_workers=2) as pool:
            applied = list(pool.map(update, (0, 0)))
        check("concurrent_updaters_serialize", all(applied) and ping(2, addresses[0]))
        before = net(0, "wg", "show", "ivpn0", "public-key").stdout
        update(0)
        check("repeat_apply_preserves_key_and_access", before == net(0, "wg", "show", "ivpn0", "public-key").stdout and ping(2, addresses[0]))
        configure_client(3)
        check("unknown_key_cannot_connect", not ping(3, addresses[0]))
        run("sudo", "ip", "-n", namespace_names[2], "address", "add", "100.100.64.253/32", "dev", "ivpn0")
        check("spoofed_source_rejected", net(2, "ping", "-I", "100.100.64.253", "-c", "1", "-W", "1", addresses[0], check=False).returncode != 0)
        run("sudo", "ip", "-n", namespace_names[2], "address", "del", "100.100.64.253/32", "dev", "ivpn0")

        http = subprocess.Popen(["sudo", "ip", "netns", "exec", namespace_names[0], "runuser", "-u", "nobody", "--",
                                 "python3", "-m", "http.server", "8088", "--bind", addresses[0], "--directory", "/var/empty"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(http)
        time.sleep(.5)
        check("private_http_reachable_over_vpn", net(2, "curl", "--noproxy", "*", "--max-time", "3", "-s", "-o", "/dev/null",
              "-w", "%{http_code}", f"http://{addresses[0]}:8088").stdout in ("200", "404"))
        check("private_http_unreachable_without_vpn", run("curl", "--noproxy", "*", "--max-time", "2", "-s", f"http://{addresses[0]}:8088", check=False).returncode != 0)

        check("remove_engineer_role", request("/api/resource/User/" + engineer, manager_token,
              {"roles": []}, method="PUT")[0] == 200)
        update(0)
        update(1)
        check("role_removal_revokes_device_network_access", not ping(2, addresses[0]) and not ping(2, addresses[1]))
        check("role_removal_denies_device_configuration", request("/api/method/internal_vpn.api.configuration?" +
              urlencode({"name": peer_names[2]}), engineer_token)[0] == 403)
        check("restore_engineer_role", request("/api/resource/User/" + engineer, manager_token,
              {"roles": [{"role": "VPN Engineer"}]}, method="PUT")[0] == 200)
        update(0)
        update(1)
        configure_client(reconnect=True)
        check("restored_role_and_reconnect_restore_access", ping(2, addresses[0]))

        if "--central" in sys.argv:
            from lab.central_integration import CentralIntegration

            central = CentralIntegration(SOURCE, directory, run_id, namespace_names[0], addresses[0], run, check)
            central.start()
            central.verify(namespace_names[2], namespace_names[1], engineer_token)
            check("central_customer_credential_not_a_vpn_credential", request(
                "/api/method/internal_vpn.api.configuration?" + urlencode({"name": peer_names[2]}),
                central.fixture["customer"]["token"])[0] in (401, 403))

        stale = api("configuration", hosts[0][1], {"name": peer_names[0]}, get=True)
        revocation = api("update_peer", engineer_token, {"name": peer_names[2], "enabled": 0})
        check("revocation_initially_pending", not api("status", manager_token, get=True)["all_current"])
        check("old_acknowledgement_rejected", request("/api/method/internal_vpn.api.report", hosts[0][1],
              {"name": peer_names[0], "revision": stale["revision"], "success": True})[0] == 417)
        update(0)
        check("partial_revocation_is_incomplete", not ping(2, addresses[0]) and ping(2, addresses[1]) and
              not api("status", manager_token, get=True)["all_current"])
        update(1)
        check("complete_revocation_blocks_both", not ping(2, addresses[0]) and not ping(2, addresses[1]) and
              api("status", manager_token, get=True)["all_current"])
        if central:
            central.verify_revocation(namespace_names[2], namespace_names[1])
        # Read only the nonsecret watermark as root; validate persisted ordering across updater processes.
        state = json.loads(run("sudo", "cat", str(host_root / "state0/revision.json")).stdout)
        watermark = directory / "watermark.json"
        watermark.write_text(json.dumps(state))
        try:
            accept_revision(watermark, stale["revision"], validate_snapshot(stale, configs[0]))
            rejected = False
        except ValueError:
            rejected = True
        check("persisted_watermark_rejects_stale_membership", rejected)
        check("service_connectivity_survives_revocation", ping(0, addresses[1]))

        revision = api("status", manager_token, get=True)["revision"]
        check("disable_owner_after_device_removal", request("/api/resource/User/" + engineer, manager_token,
              {"enabled": 0}, method="PUT")[0] == 200)
        check("disabled_peer_owner_change_preserves_revision",
              api("status", manager_token, get=True)["revision"] == revision)
        check("restore_owner_after_device_removal", request("/api/resource/User/" + engineer, manager_token,
              {"enabled": 1}, method="PUT")[0] == 200)

        api("update_peer", engineer_token, {"name": peer_names[2], "enabled": 1})
        update(0)
        update(1)
        configure_client(reconnect=True)
        check("reenabled_device_reconnects", ping(2, addresses[0]))
        rotated_private = run("wg", "genkey").stdout.strip()
        rotated_public = run("wg", "pubkey", input=rotated_private).stdout.strip()
        rotated_file = directory / "rotated.key"
        rotated_file.write_text(rotated_private)
        rotated_file.chmod(0o600)
        api("update_peer", engineer_token, {"name": peer_names[2], "public_key": rotated_public})
        update(0)
        update(1)
        net(2, "wg", "set", "ivpn0", "private-key", str(rotated_file))
        check("device_key_rotation_connects", ping(2, addresses[0]) and ping(2, addresses[1]))
        check("old_device_key_removed_from_hosts", all(public_keys[2] not in net(i, "wg", "show", "ivpn0", "peers").stdout for i in (0, 1)))
        check("disable_owner_through_frappe_api", request("/api/resource/User/" + engineer, manager_token,
              {"enabled": 0}, method="PUT")[0] == 200)
        update(0)
        update(1)
        check("owner_disablement_revokes_devices", not ping(2, addresses[0]) and not ping(2, addresses[1]))
        check("disabled_user_api_token_denied", request("/api/method/internal_vpn.api.configuration?" +
              urlencode({"name": peer_names[2]}), engineer_token)[0] in (401, 403))

        run("sudo", "ip", "-n", namespace_names[0], "link", "del", "ivpn0")
        check("missing_interface_reports_apply_failure", not update(0, expect=False) and
              not api("status", manager_token, get=True)["all_current"])
        interface = f"iv{run_id}0"
        run("sudo", "ip", "link", "add", interface, "type", "wireguard")
        run("sudo", "ip", "link", "set", interface, "netns", namespace_names[0])
        run("sudo", "ip", "-n", namespace_names[0], "link", "set", interface, "name", "ivpn0")
        net(0, "wg", "set", "ivpn0", "private-key", str(directory / "key0"), "listen-port", "56441")
        run("sudo", "ip", "-n", namespace_names[0], "address", "add", addresses[0] + "/24", "dev", "ivpn0")
        run("sudo", "ip", "-n", namespace_names[0], "link", "set", "ivpn0", "up")
        update(0)
        check("interface_restart_reapplies_current_peers", ping(0, addresses[1]) and api("status", manager_token, get=True)["all_current"])
        check("interface_restart_preserves_revocation", not ping(2, addresses[0]))

        api("update_peer", manager_token, {"name": peer_names[1], "enabled": 0})
        update(0)
        update(1)
        check("disabled_service_applies_empty_configuration", not net(1, "wg", "show", "ivpn0", "peers").stdout.strip())
        check("disable_drained_service_account", request("/api/resource/User/" + hosts[1][0], manager_token,
              {"enabled": 0}, method="PUT")[0] == 200)
        check("drained_service_account_change_preserves_acknowledgements", api("status", manager_token, get=True)["all_current"])
        private = run("wg", "genkey").stdout.strip()
        public = run("wg", "pubkey", input=private).stdout.strip()
        api("register", other_engineer_token, {"kind": "Device", "public_key": public})
        update(0)
        # Expected evidence of the retirement gap, not a successful retirement acceptance test.
        check("retired_service_still_blocks_later_revision_status", not api("status", manager_token, get=True)["all_current"])

finally:
    for name in namespaces:
        pids = run("sudo", "ip", "netns", "pids", name, check=False).stdout.split()
        if pids:
            run("sudo", "kill", *pids, check=False)
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
    for name in reversed(namespaces):
        run("sudo", "ip", "netns", "del", name, check=False)
    run("sudo", "rm", "-rf", "--", str(host_root))
    # Only this run's identities; the dedicated lab site and schema remain reusable.
    import frappe
    frappe.destroy()
    os.chdir(BASE / "sites")
    frappe.init("test.local")
    frappe.connect()
    if frappe.conf.db_name == "ivpn_poc":
        for user in users:
            frappe.db.delete("VPN Peer", {"user": user})
            frappe.delete_doc("User", user, ignore_permissions=True, force=True)
        frappe.db.commit()
    frappe.destroy()
    remaining = run("sudo", "ip", "netns", "list").stdout
    results["temporary_namespaces_removed"] = all(name not in remaining for name in namespaces)
    (SOURCE / "lab-results.json").write_text(json.dumps(results, indent=2) + "\n")
    if central:
        (SOURCE / "central-results.json").write_text(json.dumps({"source_sha256": getattr(central, "fixture", {}).get("source_sha256"),
            "checks": {name: value for name, value in results.items() if "central" in name}}, indent=2) + "\n")
    print(json.dumps(results, indent=2), flush=True)

if not results or not all(results.values()):
    raise SystemExit(1)
