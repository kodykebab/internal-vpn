"""Bounded peer-count and overlay impairment checks on disposable namespaces."""

import json
import re
import select
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor


def verify_peer_scale(
    configs,
    hosts,
    engineer_token,
    manager_token,
    *,
    api,
    run,
    run_in_namespace,
    update,
    ping,
    check,
    observations,
):
    count = 64
    before_spoke = api("configuration", hosts[1][1], {"name": configs[1]["name"]}, get=True)
    keys = []
    for _ in range(count):
        private = run("wg", "genkey").stdout
        keys.append(run("wg", "pubkey", input=private).stdout.strip())

    def enroll(key):
        start = time.monotonic()
        record = api("register", engineer_token, {"kind": "Device", "public_key": key})
        return record, time.monotonic() - start

    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=4) as pool:
        enrolled = list(pool.map(enroll, keys))
    observations["scale"] = {
        "extra_peers": count,
        "enrollment_concurrency": 4,
        "enrollment_wall_seconds": time.monotonic() - start,
        "enrollment_request_seconds": [duration for _, duration in enrolled],
    }
    check(
        "scale_allocates_unique_addresses_and_revisions",
        len({record["address"] for record, _ in enrolled}) == count
        and len({record["revision"] for record, _ in enrolled}) == count,
    )
    start = time.monotonic()
    snapshot = api("configuration", hosts[0][1], {"name": configs[0]["name"]}, get=True)
    observations["scale"]["hub_snapshot_seconds"] = time.monotonic() - start
    observations["scale"]["hub_peer_count"] = len(snapshot["peers"])
    observations["scale"]["hub_snapshot_json_bytes"] = len(
        json.dumps(snapshot, separators=(",", ":")).encode()
    )
    start = time.monotonic()
    update(0)
    observations["scale"]["hub_apply_and_report_seconds"] = time.monotonic() - start
    actual = set(run_in_namespace(0, "wg", "show", "ivpn0", "peers").stdout.split())
    check(
        "scale_hub_applies_all_enrolled_peers", actual == {peer["public_key"] for peer in snapshot["peers"]}
    )
    after_spoke = api("configuration", hosts[1][1], {"name": configs[1]["name"]}, get=True)
    check(
        "scale_spoke_configuration_stays_constant",
        after_spoke["peers"] == before_spoke["peers"] and len(after_spoke["peers"]) == 1,
    )
    check(
        "scale_active_services_stay_current_and_connected",
        api("status", manager_token, get=True)["all_current"] and ping(4, configs[1]["address"]),
    )
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(
            pool.map(
                lambda item: api("update_peer", engineer_token, {"name": item[0]["name"], "enabled": 0}),
                enrolled,
            )
        )
    observations["scale"]["disable_batch_seconds"] = time.monotonic() - start
    start = time.monotonic()
    update(0)
    observations["scale"]["remove_batch_apply_and_report_seconds"] = time.monotonic() - start
    check(
        "scale_disabled_peers_removed_without_spoke_refresh",
        not set(keys).intersection(run_in_namespace(0, "wg", "show", "ivpn0", "peers").stdout.split())
        and api("status", manager_token, get=True)["all_current"],
    )


def verify_network_conditions(
    source, namespaces, configs, *, run, run_in_namespace, ping, check, observations
):
    mtus = {
        i: json.loads(run("sudo", "ip", "-j", "-n", namespaces[i], "link", "show", "ivpn0").stdout)[0]["mtu"]
        for i in (0, 1, 4)
    }
    server = None
    server_pid = None
    shaped = []
    observations["network"] = {
        "cap_mbps": 20,
        "transfer_bytes_per_scenario": 2097152,
        "impaired_egress_delay_ms_each_spoke": 20,
        "impaired_egress_loss_percent_each_spoke": 1,
    }
    fixture = (source / "lab/transfer.py").read_text()

    def shape(impaired):
        for i in (1, 4):
            arguments = ["delay", "20ms", "loss", "1%"] if impaired else []
            run_in_namespace(
                i, "tc", "qdisc", "replace", "dev", "ivpn0", "root", "netem", *arguments, "rate", "20mbit"
            )
            if i not in shaped:
                shaped.append(i)

    def transfer(label):
        result = json.loads(
            run_in_namespace(
                4, "runuser", "-u", "nobody", "--", "python3", "-c", fixture, "client", configs[1]["address"]
            ).stdout
        )
        observations["network"][label] = result
        check("network_" + label + "_transfer_integrity", result["valid"] and result["bytes"] == 2097152)

    try:
        shape(False)
        server = subprocess.Popen(
            [
                "sudo",
                "ip",
                "netns",
                "exec",
                namespaces[1],
                "runuser",
                "-u",
                "nobody",
                "--",
                "python3",
                "-c",
                fixture,
                "server",
                configs[1]["address"],
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if not select.select([server.stdout], [], [], 5)[0]:
            raise RuntimeError("Transfer fixture did not start")
        server_pid = json.loads(server.stdout.readline())["pid"]
        transfer("baseline")
        shape(True)
        probe = run_in_namespace(
            4, "ping", "-n", "-c", "5", "-i", ".2", "-W", "1", configs[1]["address"], check=False
        )
        latencies = [float(value) for value in re.findall(r"time=([0-9.]+) ms", probe.stdout)]
        observations["network"]["impaired_ping_rtt_ms"] = latencies
        check("network_added_latency_observed", bool(latencies) and min(latencies) >= 30)
        transfer("impaired")
        stats = {
            str(i): json.loads(run_in_namespace(i, "tc", "-s", "-j", "qdisc", "show", "dev", "ivpn0").stdout)
            for i in (1, 4)
        }
        dropped = sum(qdisc.get("drops", 0) for values in stats.values() for qdisc in values)
        observations["network"]["impaired_qdisc_drops"] = dropped
        check("network_packet_loss_exercised", dropped > 0)
        shape(False)
        run("sudo", "ip", "-n", namespaces[0], "link", "set", "ivpn0", "mtu", "1280")
        small = run_in_namespace(
            4,
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            "2",
            "-M",
            "do",
            "-s",
            "1252",
            configs[1]["address"],
            check=False,
        )
        large = run_in_namespace(
            4,
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            "2",
            "-M",
            "do",
            "-s",
            "1300",
            configs[1]["address"],
            check=False,
        )
        check("network_reduced_hub_mtu_passes_fitting_packet", small.returncode == 0)
        check(
            "network_reduced_hub_mtu_reports_oversize_df_packet",
            large.returncode != 0 and "1280" in large.stdout + large.stderr,
        )
        observations["network"]["reduced_hub_mtu"] = 1280
        transfer("reduced_mtu")
        server.wait(timeout=5)
        server_pid = None
        check("network_transfer_server_exits_cleanly", server.returncode == 0)
    finally:
        if server is not None and server.poll() is None:
            if server_pid:
                run("sudo", "kill", "-TERM", str(server_pid), check=False)
            else:
                run("sudo", "pkill", "-TERM", "-P", str(server.pid), check=False)
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
        for i in shaped:
            run_in_namespace(i, "tc", "qdisc", "del", "dev", "ivpn0", "root", check=False)
        for i, mtu in mtus.items():
            run("sudo", "ip", "-n", namespaces[i], "link", "set", "ivpn0", "mtu", str(mtu))
    check(
        "network_conditions_restored",
        ping(4, configs[1]["address"])
        and all(
            json.loads(run("sudo", "ip", "-j", "-n", namespaces[i], "link", "show", "ivpn0").stdout)[0]["mtu"]
            == mtu
            for i, mtu in mtus.items()
        )
        and all(
            all(
                q["kind"] != "netem"
                for q in json.loads(run_in_namespace(i, "tc", "-j", "qdisc", "show", "dev", "ivpn0").stdout)
            )
            for i in shaped
        ),
    )
