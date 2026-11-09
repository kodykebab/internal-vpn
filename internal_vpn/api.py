import frappe

from internal_vpn import validation


def require_role(role):
    if role not in frappe.get_roles():
        raise frappe.PermissionError(f"{role} required")


def validated(parser, value):
    try:
        return parser(value)
    except (TypeError, ValueError) as error:
        raise frappe.ValidationError(str(error)) from None


def locked_network():
    # Every membership write and snapshot uses this row: allocation and revision are atomic.
    return frappe.db.sql("SELECT * FROM `tabVPN Network` WHERE name='default' FOR UPDATE", as_dict=True)[0]


def advance(network):
    revision = network.revision + 1
    frappe.db.set_value("VPN Network", "default", "revision", revision, update_modified=False)
    return revision


def current_peers():
    # Frappe authentication can establish a REPEATABLE READ snapshot before our lock.
    # Locking reads must also fetch membership at the revision we just locked.
    return frappe.db.sql("SELECT * FROM `tabVPN Peer` ORDER BY name FOR UPDATE", as_dict=True)


def eligible_user(user, role):
    rows = frappe.db.sql("SELECT enabled FROM `tabUser` WHERE name=%s FOR UPDATE", user)
    roles = frappe.db.sql(
        "SELECT role FROM `tabHas Role` WHERE parent=%s AND parenttype='User' FOR UPDATE", user)
    return bool(rows and rows[0][0] and role in {r[0] for r in roles})


def save_peer(doc):
    doc.flags.vpn_mutation = True
    doc.save(ignore_permissions=True)


def active(peer):
    role = "VPN Host" if peer.kind == "Service" else "VPN Engineer"
    return bool(peer.enabled and eligible_user(peer.user, role))


@frappe.whitelist(methods=["POST"])
def initialize(subnet):
    require_role("VPN Manager")
    value = str(validated(validation.subnet, subnet))
    network = locked_network()
    if network.subnet and network.subnet != value:
        raise frappe.ValidationError("Readdressing an existing network is outside this PoC")
    if not network.subnet:
        frappe.db.set_value("VPN Network", "default", "subnet", value)
        advance(network)
    return {"subnet": value}


@frappe.whitelist(methods=["POST"])
def register(kind, public_key, user=None, endpoint=None):
    if kind == "Service":
        require_role("VPN Manager")
        endpoint = validated(validation.endpoint, endpoint)
        if not user or "VPN Host" not in frappe.get_roles(user):
            raise frappe.ValidationError("Service requires a VPN Host user")
    elif kind == "Device":
        require_role("VPN Engineer")
        if user and user != frappe.session.user:
            raise frappe.PermissionError("Register only your own device")
        user, endpoint = frappe.session.user, None
    else:
        raise frappe.ValidationError("Expected Service or Device")
    public_key = validated(validation.public_key, public_key)
    network = locked_network()
    if not eligible_user(user, "VPN Host" if kind == "Service" else "VPN Engineer"):
        raise frappe.ValidationError("Owner must be enabled and have the required VPN role")
    if not network.subnet:
        raise frappe.ValidationError("Initialize the subnet first")
    peers = current_peers()
    if kind == "Service" and any(p.user == user and p.kind == "Service" for p in peers):
        raise frappe.ValidationError("Use one dedicated user per service")
    used = {p.address for p in peers}
    address = next((str(ip) for ip in validation.subnet(network.subnet).hosts() if str(ip) not in used), None)
    if address is None:
        raise frappe.ValidationError("Subnet exhausted")
    doc = frappe.get_doc(dict(doctype="VPN Peer", kind=kind, user=user, public_key=public_key,
                              endpoint=endpoint, address=address, enabled=1))
    save_peer(doc)
    return {"name": doc.name, "address": address, "revision": advance(network)}


@frappe.whitelist(methods=["POST"])
def update_peer(name, enabled=None, public_key=None, endpoint=None):
    manager = "VPN Manager" in frappe.get_roles()
    if not manager:
        require_role("VPN Engineer")
    network = locked_network()
    peer = frappe.get_doc("VPN Peer", name, for_update=True)
    if not manager:
        if peer.kind != "Device" or peer.user != frappe.session.user:
            raise frappe.PermissionError("Not your device")
    if enabled is not None:
        if type(enabled) not in (bool, int, str) or enabled not in (0, 1, "0", "1"):
            raise frappe.ValidationError("enabled must be 0 or 1")
        peer.enabled = int(enabled)
    if public_key is not None:
        peer.public_key = validated(validation.public_key, public_key)
    if endpoint is not None:
        if peer.kind != "Service":
            raise frappe.ValidationError("Device endpoints are learned by WireGuard")
        peer.endpoint = validated(validation.endpoint, endpoint)
    save_peer(peer)
    return {"revision": advance(network)}


def own_peer(name):
    peer = frappe.get_doc("VPN Peer", name, for_update=True)
    if peer.user != frappe.session.user:
        raise frappe.PermissionError("This credential belongs to another peer")
    require_role("VPN Host" if peer.kind == "Service" else "VPN Engineer")
    return peer


@frappe.whitelist(methods=["GET"])
def configuration(name):
    if not {"VPN Host", "VPN Engineer"}.intersection(frappe.get_roles()):
        raise frappe.PermissionError("VPN identity required")
    network = locked_network()
    peer = own_peer(name)
    peers = []
    if active(peer):
        for other in current_peers():
            if other.name != name and active(other):
                peers.append({"public_key": other.public_key, "address": other.address,
                              "endpoint": other.endpoint or None})
    return {"version": 1, "name": peer.name, "revision": network.revision, "subnet": network.subnet,
            "address": peer.address, "public_key": peer.public_key, "peers": peers}


@frappe.whitelist(methods=["POST"])
def report(name, revision, success):
    require_role("VPN Host")
    if type(revision) is not int or revision < 1:
        raise frappe.ValidationError("Expected a positive integer revision")
    if type(success) is not bool:
        raise frappe.ValidationError("Expected boolean success")
    network = locked_network()
    peer = own_peer(name)
    if peer.kind != "Service":
        raise frappe.PermissionError("Only service hosts report application")
    if revision != network.revision:
        raise frappe.ValidationError("Outdated application report; fetch current configuration")
    frappe.db.set_value("VPN Peer", name, {
        "reported_revision": revision, "apply_success": int(success),
        "reported_at": frappe.utils.now_datetime(),
    }, update_modified=False)
    return {"accepted": True}


@frappe.whitelist(methods=["GET"])
def status():
    require_role("VPN Manager")
    network = locked_network()
    fields = ("name", "enabled", "reported_revision", "apply_success", "reported_at")
    hosts = [frappe._dict({field: peer[field] for field in fields})
             for peer in current_peers() if peer.kind == "Service"]
    for host in hosts:
        host["current"] = bool(host.apply_success and host.reported_revision == network.revision)
    return {"revision": network.revision, "hosts": hosts, "all_current": bool(hosts) and all(h.current for h in hosts)}


def user_changed(doc, method=None):
    previous = doc.get_doc_before_save()
    relevant_roles = {"VPN Host", "VPN Engineer"}
    if method != "on_trash" and previous:
        previous_roles = {row.role for row in previous.roles} & relevant_roles
        current_roles = {row.role for row in doc.roles} & relevant_roles
        if previous.enabled == doc.enabled and previous_roles == current_roles:
            return
    if not frappe.db.exists("DocType", "VPN Network") or not frappe.db.exists("VPN Network", "default"):
        return
    network = locked_network()
    if any(peer.user == doc.name and peer.enabled for peer in current_peers()):
        advance(network)
