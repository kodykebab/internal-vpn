app_name = "internal_vpn"
app_title = "Internal VPN"
app_publisher = "Frappe"
app_description = "Internal VPN control plane"
app_email = "developers@frappe.io"
app_license = "mit"

after_install = "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.after_install"
auth_hooks = ["internal_vpn.wsgi.require_login"]
doc_events = {
    "User": {
        "on_update": "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.on_user_change",
        "on_trash": "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.on_user_change",
    }
}
has_permission = {"VPN Peer": "internal_vpn.internal_vpn.doctype.vpn_peer.vpn_peer.has_permission"}
permission_query_conditions = {
    "VPN Peer": "internal_vpn.internal_vpn.doctype.vpn_peer.vpn_peer.get_permission_query_conditions"
}
