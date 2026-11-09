"""Live kill/reconcile boundaries and small-sample convergence observations."""

import json
import subprocess
import time


def verify(
    source,
    host_root,
    device,
    token,
    manager_token,
    key,
    hub_address,
    *,
    api,
    run,
    run_in_namespace,
    update,
    configure_client,
    ping,
    check,
    record_timing,
):
    wrapper = host_root / "interrupted-host.py"
    run("sudo", "install", "-m", "0644", str(source / "lab/interrupted_host.py"), str(wrapper))
    state = host_root / "state0"

    def hub_has_device():
        return key in run_in_namespace(0, "wg", "show", "ivpn0", "peers").stdout.split()

    def kill_at_boundary(phase, revision):
        marker = host_root / ("interrupt-" + phase + ".json")
        process = subprocess.Popen(
            [
                "sudo",
                "python3",
                str(wrapper),
                "--phase",
                phase,
                "--marker",
                str(marker),
                "--config",
                str(host_root / "host0.json"),
                "--state",
                str(state),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pid = None
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                result = run("sudo", "cat", str(marker), check=False)
                if result.returncode == 0:
                    pid = json.loads(result.stdout)["pid"]
                    break
                time.sleep(0.1)
            check("interrupted_" + phase + "_reaches_real_boundary", pid is not None)
            accepted = json.loads(run("sudo", "cat", str(state / "revision.json")).stdout)
            check("interrupted_" + phase + "_persists_revision_before_kill", accepted["revision"] == revision)
            run("sudo", "kill", "-KILL", str(pid))
            process.wait(timeout=10)
            pid = None
            check(
                "interrupted_" + phase + "_has_no_success_ack",
                not api("status", manager_token, get=True)["hub_current"],
            )
        finally:
            if pid is not None:
                run("sudo", "kill", "-KILL", str(pid), check=False)
            if process.poll() is None:
                # Stop only this test's sudo/child tree if it did not reach its marker.
                run("sudo", "pkill", "-KILL", "-P", str(process.pid), check=False)
                process.kill()
                process.wait(timeout=10)

    revision = api("update_peer", token, {"name": device, "enabled": 0})["revision"]
    kill_at_boundary("remove", revision)
    check("interrupted_removal_stays_revoked", not hub_has_device() and not ping(2, hub_address))
    start = time.monotonic()
    update(0)
    record_timing("interrupted_remove_next_run_seconds", time.monotonic() - start)
    check(
        "interrupted_removal_next_run_finishes",
        api("status", manager_token, get=True)["hub_current"] and not hub_has_device(),
    )

    revision = api("update_peer", token, {"name": device, "enabled": 1})["revision"]
    kill_at_boundary("report", revision)
    configure_client(reconnect=True)
    check("interrupted_report_keeps_applied_tunnel", hub_has_device() and ping(2, hub_address))
    start = time.monotonic()
    update(0)
    record_timing("interrupted_report_next_run_seconds", time.monotonic() - start)
    check("interrupted_report_next_run_acknowledges", api("status", manager_token, get=True)["all_current"])

    revoke, enroll = [], []
    for _ in range(3):
        start = time.monotonic()
        api("update_peer", token, {"name": device, "enabled": 0})
        update(0)
        revoke.append(time.monotonic() - start)
        check("measured_revocation_removes_peer", not hub_has_device() and not ping(2, hub_address))
        start = time.monotonic()
        api("update_peer", token, {"name": device, "enabled": 1})
        update(0)
        enroll.append(time.monotonic() - start)
        configure_client(reconnect=True)
        check("measured_reenrollment_restores_access", ping(2, hub_address))
    record_timing("direct_revocation_api_to_ack_seconds", revoke)
    record_timing("direct_reenrollment_api_to_ack_seconds", enroll)
