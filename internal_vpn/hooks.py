app_name = "internal_vpn"
app_title = "Internal VPN"
app_publisher = "Frappe"
app_description = "Internal VPN control plane"
app_email = "developers@frappe.io"
app_license = "mit"

add_to_apps_screen = [
    {
        "name": "internal_vpn",
        "title": "Internal VPN",
        "logo": "/assets/frappe/images/frappe-framework-logo.svg",
        "route": "/desk/vpn-device",
        "has_permission": "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.has_desk_access",
    }
]

fixtures = [{"dt": "Role", "filters": [["name", "in", ["VPN Manager", "VPN Engineer", "VPN Host"]]]}]
after_install = "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.after_install"
user_invitation = {"allowed_roles": {"VPN Manager": ["VPN Engineer"]}}
doc_events = {
    "User": {
        "on_update": "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.on_user_change",
        "on_trash": "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.on_user_change",
    }
}
scheduler_events = {
    "cron": {"*/5 * * * *": ["internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.check_hub"]}
}
