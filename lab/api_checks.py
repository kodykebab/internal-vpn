"""API input validation and permission checks."""

from urllib.parse import urlencode


def verify(
    *,
    api,
    request,
    check,
    manager_token,
    engineer_token,
    other_engineer_token,
    outsider_token,
    host_token,
    peer_names,
):
    path = "/api/method/internal_vpn.api."
    revision = api("status", manager_token, get=True)["revision"]
    check(
        "invalid_public_key_is_client_error",
        request(path + "register", engineer_token, {"kind": "Device", "public_key": "invalid"})[0] == 417,
    )
    check(
        "invalid_subnet_is_client_error",
        request(path + "initialize", manager_token, {"subnet": "192.168.0.0/24"})[0] == 417,
    )
    check(
        "invalid_endpoint_is_client_error",
        request(
            path + "update_peer",
            manager_token,
            {"name": peer_names[0], "endpoint": "$(touch /tmp/not-executed):22"},
        )[0]
        == 417,
    )
    check(
        "floating_enabled_value_rejected",
        request(path + "update_peer", engineer_token, {"name": peer_names[2], "enabled": 1.0})[0] == 417,
    )
    check(
        "floating_revision_rejected",
        request(
            path + "report", host_token, {"name": peer_names[0], "revision": float(revision), "success": True}
        )[0]
        == 417,
    )
    check(
        "numeric_success_rejected",
        request(path + "report", host_token, {"name": peer_names[0], "revision": revision, "success": 1})[0]
        == 417,
    )
    check(
        "nonmember_unknown_peer_denied_before_lookup",
        request(path + "update_peer", outsider_token, {"name": "does-not-exist", "enabled": 0})[0] == 403,
    )
    check(
        "other_engineer_cannot_modify_device",
        request(path + "update_peer", other_engineer_token, {"name": peer_names[2], "enabled": 0})[0] == 403,
    )
    check(
        "other_engineer_cannot_fetch_device",
        request(path + "configuration?" + urlencode({"name": peer_names[2]}), other_engineer_token)[0] == 403,
    )
    check(
        "guest_login_post_cannot_dispatch_other_method",
        request("/api/method/login", data={"cmd": "frappe.ping"})[0] in (401, 403),
    )
    status, body = request("/api/resource/VPN%20Peer/" + peer_names[2], manager_token)
    check("manager_can_read_membership", status == 200)
    doc = body["data"]
    doc.update(enabled=0, flags={"ignore_permissions": True, "vpn_mutation": True})
    check(
        "client_flags_cannot_bypass_membership_api",
        request("/api/method/frappe.client.save", manager_token, {"doc": doc})[0] == 403,
    )
    check(
        "rejected_requests_do_not_advance_revision",
        api("status", manager_token, get=True)["revision"] == revision,
    )
