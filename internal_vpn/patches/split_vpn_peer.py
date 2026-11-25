import frappe
from frappe.query_builder import DocType
from frappe.share import add_docshare

COMMON_FIELDS = ("name", "label", "public_key", "address", "enabled", "creation", "modified")
REPORT_FIELDS = ("reported_revision", "apply_success", "reported_at", "reported_digest")


def execute():
    """Move VPN Peer rows to VPN Server and VPN Device, and the `default` network to the Single."""
    if not frappe.db.table_exists("VPN Peer"):
        return
    peer_table, network_table = DocType("VPN Peer"), DocType("VPN Network")
    network = (
        frappe.qb.from_(network_table).select("*").where(network_table.name == "default").run(as_dict=True)
    )
    network = network[0] if network else frappe._dict()
    hub_endpoint = None

    for peer in frappe.qb.from_(peer_table).select("*").run(as_dict=True):
        values = {field: peer[field] for field in COMMON_FIELDS}
        if peer.kind == "Service":
            doc = frappe.get_doc({"doctype": "VPN Server", **values, "user": peer.user, "owner": peer.owner})
            doc.update({field: peer[field] for field in REPORT_FIELDS})
            if peer.name == network.hub:
                hub_endpoint = peer.endpoint
        else:
            doc = frappe.get_doc({"doctype": "VPN Device", **values, "owner": peer.user})
        doc.db_insert()
        if doc.doctype == "VPN Server":
            add_docshare(
                doc.doctype, doc.name, doc.user, read=1, agent=1, flags={"ignore_share_permission": True}
            )

    # The next revision makes every host fetch the migrated membership.
    frappe.db.set_single_value(
        "VPN Network",
        {
            "subnet": network.subnet,
            "hub": network.hub,
            "hub_endpoint": hub_endpoint,
            "revision": (network.revision or 0) + 1,
            "hub_digest": None,
            "hub_alert": network.hub_alert,
        },
    )
    # Migrate removes the orphan VPN Peer DocType but keeps tables; the rows are moved, so drop them.
    frappe.db.sql_ddl("DROP TABLE IF EXISTS `tabVPN Peer`")
    frappe.db.sql_ddl("DROP TABLE IF EXISTS `tabVPN Network`")
