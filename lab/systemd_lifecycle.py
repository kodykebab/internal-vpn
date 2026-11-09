"""Exercise the deployment units with a disposable interface and runtime units.

No host address/routes are installed. Keep the production capability restrictions;
namespace switching would require extra privileges absent from the real unit.
"""

import json
import time
from pathlib import Path


def verify(source, directory, host_root, config, namespace, run_id, *, run, check, record_timing):
    name = "ivpn-poc-" + run_id
    interface = "it" + run_id
    state = Path("/var/lib") / name
    service = name + ".service"
    timer = name + ".timer"
    units = [Path("/run/systemd/system") / unit for unit in (service, timer)]
    installed = False
    moved = False

    def systemctl(*args, **kwargs):
        return run("sudo", "systemctl", *args, **kwargs)

    def service_property(prop):
        return systemctl("show", service, "--property=" + prop, "--value").stdout.strip()

    def wait_for(predicate, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.5)
        return False

    def collect_metrics():
        return json.loads(
            run(
                "sudo",
                "python3",
                str(host_root / "run-metrics.py"),
                "--config",
                str(host_root / "systemd.json"),
                "--unit",
                service,
            ).stdout
        )

    def peers():
        return run("sudo", "wg", "show", interface, "peers").stdout.strip()

    try:
        # Move only the existing disposable spoke, stripping its address first.
        run("sudo", "ip", "-n", namespace, "address", "flush", "dev", "ivpn0")
        run("sudo", "ip", "-n", namespace, "link", "set", "ivpn0", "down")
        run("sudo", "ip", "-n", namespace, "link", "set", "ivpn0", "name", interface)
        run("sudo", "ip", "-n", namespace, "link", "set", interface, "netns", "1")
        moved = True
        local = dict(config, interface=interface, ca_file=str(host_root / "systemd-ca.crt"))
        local.pop("namespace")
        path = directory / "systemd.json"
        path.write_text(json.dumps(local))
        path.chmod(0o600)
        run("sudo", "install", "-m", "0600", str(path), str(host_root / "systemd.json"))
        path.unlink()
        run("sudo", "install", "-m", "0644", config["ca_file"], local["ca_file"])
        text = (source / "deploy/internal-vpn-update.service").read_text()
        text = text.replace("/opt/internal-vpn", str(host_root)).replace(
            "/etc/internal-vpn/host.json", str(host_root / "systemd.json")
        )
        text = text.replace("/var/lib/internal-vpn", str(state)).replace(
            "StateDirectory=internal-vpn", "StateDirectory=" + name
        )
        texts = [
            text,
            (source / "deploy/internal-vpn-update.timer")
            .read_text()
            .replace("internal-vpn-update.service", service),
        ]
        for destination, text in zip(units, texts):
            path = directory / destination.name
            path.write_text(text)
            run("sudo", "install", "-m", "0644", str(path), str(destination))
        installed = True
        run("sudo", "systemd-analyze", "verify", *(str(unit) for unit in units))
        systemctl("daemon-reload")
        run("sudo", "wg", "set", interface, "peer", config["hub_public_key"], "remove")
        # Keep the service referenced by its active timer, as in deployment.
        # Unreferenced completed oneshots can be unloaded and lose execution metadata.
        systemctl("start", timer)
        systemctl("start", service)
        check(
            "systemd_service_applies_with_production_sandbox",
            peers() == config["hub_public_key"] and service_property("Result") == "success",
        )
        check(
            "systemd_creates_private_state_directory",
            run("sudo", "stat", "-c", "%u:%a", str(state)).stdout.strip() == "0:700",
        )
        check(
            "systemd_credentials_unreadable_by_app_user",
            run("cat", str(host_root / "systemd.json"), check=False).returncode != 0,
        )
        check(
            "metrics_reports_successful_updater_run", collect_metrics()["updater"]["last_result"] == "success"
        )
        watermark = run("sudo", "cat", str(state / "revision.json")).stdout

        run("sudo", "chmod", "0644", str(host_root / "systemd.json"))
        check(
            "systemd_rejects_insecure_config_permissions",
            systemctl("start", service, check=False).returncode != 0,
        )
        run("sudo", "chmod", "0600", str(host_root / "systemd.json"))
        run("sudo", "ip", "link", "set", interface, "name", interface + "x")
        try:
            check(
                "systemd_missing_interface_fails",
                systemctl("start", service, check=False).returncode != 0
                and service_property("Result") == "exit-code",
            )
        finally:
            run("sudo", "ip", "link", "set", interface + "x", "name", interface)
        check(
            "metrics_reports_failed_updater_run",
            collect_metrics()["updater"]["last_result"] == "exit-code"
            and collect_metrics()["updater"]["last_exit_status"] != 0,
        )
        systemctl("start", timer)
        check(
            "systemd_timer_recovers_failed_apply",
            wait_for(
                lambda: (
                    service_property("Result") == "success" and service_property("ActiveState") == "inactive"
                )
            ),
        )
        start = time.monotonic()
        run("sudo", "wg", "set", interface, "peer", config["hub_public_key"], "remove")
        check(
            "systemd_timer_reconciles_live_peer_drift", wait_for(lambda: peers() == config["hub_public_key"])
        )
        record_timing("timer_peer_drift_repair_seconds", time.monotonic() - start)
        systemctl("stop", timer)
        systemctl("stop", service)
        systemctl("start", service)
        check(
            "systemd_restart_preserves_revision_watermark",
            watermark == run("sudo", "cat", str(state / "revision.json")).stdout,
        )
    finally:
        if installed:
            systemctl("stop", timer, service, check=False)
            systemctl("reset-failed", service, check=False)
        for unit in units:
            run("sudo", "rm", "-f", "--", str(unit))
        systemctl("daemon-reload")
        run("sudo", "rm", "-rf", "--", str(state))
        if moved:
            run("sudo", "ip", "link", "set", interface, "netns", namespace)
        run("sudo", "ip", "-n", namespace, "link", "set", interface, "name", "ivpn0")
        run("sudo", "ip", "-n", namespace, "address", "add", config["address"] + "/24", "dev", "ivpn0")
        run("sudo", "ip", "-n", namespace, "link", "set", "ivpn0", "up")
        check(
            "systemd_runtime_units_and_state_removed",
            all(not unit.exists() for unit in units) and not state.exists(),
        )
