app_name = "internal_vpn"
app_title = "Internal VPN"
app_publisher = "Frappe"
app_description = "Internal VPN control plane"
app_email = "developers@frappe.io"
app_license = "mit"
export_python_type_annotations = True

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
auth_hooks = ["internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.require_vpn"]
override_whitelisted_methods = {
    "frappe.www.login.login_via_key": "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.login_via_key"
}
doc_events = {
    "User": {
        "on_update": "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.on_user_change",
        "on_trash": "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.on_user_change",
    }
}
scheduler_events = {
    "cron": {
        "* * * * *": [
            "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.apply_hub",
            "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.refresh_statuses",
        ]
    }
}
