import frappe

from internal_vpn import topology, validation


def require_role(role):
    if role not in frappe.get_roles():
        raise frappe.PermissionError(f"{role} required")


def validate_input(parser, value):
    try:
        return parser(value)
    except (TypeError, ValueError) as error:
        raise frappe.ValidationError(str(error)) from None


def get_locked_network():
    # Every membership write and snapshot uses this row: allocation and revision are atomic.
    return frappe.db.sql("SELECT * FROM `tabVPN Network` WHERE name='default' FOR UPDATE", as_dict=True)[0]


def advance_revision(network):
    revision = network.revision + 1
    frappe.db.set_value("VPN Network", "default", "revision", revision, update_modified=False)
    return revision


def get_locked_peers():
    # Frappe authentication can establish a REPEATABLE READ snapshot before our lock.
    # Locking reads must also fetch membership at the revision we just locked.
    return frappe.db.sql("SELECT * FROM `tabVPN Peer` ORDER BY name FOR UPDATE", as_dict=True)


def is_user_eligible(user, role):
    rows = frappe.db.sql("SELECT enabled FROM `tabUser` WHERE name=%s FOR UPDATE", user)
    roles = frappe.db.sql(
        "SELECT role FROM `tabHas Role` WHERE parent=%s AND parenttype='User' FOR UPDATE", user
    )
    return bool(rows and rows[0][0] and role in {r[0] for r in roles})


def save_peer(doc):
    doc.flags.vpn_mutation = True
    doc.save(ignore_permissions=True)


def is_peer_active(peer):
    role = "VPN Host" if peer.kind == "Service" else "VPN Engineer"
    return bool(peer.enabled and is_user_eligible(peer.user, role))


@frappe.whitelist(methods=["POST"])
def initialize(subnet):
    require_role("VPN Manager")
    value = str(validate_input(validation.subnet, subnet))
    network = get_locked_network()
    if network.subnet and network.subnet != value:
        raise frappe.ValidationError("Readdressing an existing network is outside this PoC")
    if not network.subnet:
        frappe.db.set_value("VPN Network", "default", "subnet", value)
        advance_revision(network)
    return {"subnet": value}


@frappe.whitelist(methods=["POST"])
def register(kind, public_key, user=None, endpoint=None):
    if kind == "Service":
        require_role("VPN Manager")
        endpoint = validate_input(validation.endpoint, endpoint) if endpoint is not None else None
        if not user or "VPN Host" not in frappe.get_roles(user):
            raise frappe.ValidationError("Service requires a VPN Host user")
    elif kind == "Device":
        require_role("VPN Engineer")
        if user and user != frappe.session.user:
            raise frappe.PermissionError("Register only your own device")
        user, endpoint = frappe.session.user, None
    else:
        raise frappe.ValidationError("Expected Service or Device")
    public_key = validate_input(validation.public_key, public_key)
    network = get_locked_network()
    if not is_user_eligible(user, "VPN Host" if kind == "Service" else "VPN Engineer"):
        raise frappe.ValidationError("Owner must be enabled and have the required VPN role")
    if not network.subnet:
        raise frappe.ValidationError("Initialize the subnet first")
    peers = get_locked_peers()
    if kind == "Service" and any(p.user == user and p.kind == "Service" for p in peers):
        raise frappe.ValidationError("Use one dedicated user per service")
    used = {p.address for p in peers}
    address = next((str(ip) for ip in validation.subnet(network.subnet).hosts() if str(ip) not in used), None)
    if address is None:
        raise frappe.ValidationError("Subnet exhausted")
    doc = frappe.get_doc(
        {
            "doctype": "VPN Peer",
            "kind": kind,
            "user": user,
            "public_key": public_key,
            "endpoint": endpoint,
            "address": address,
            "enabled": 1,
        }
    )
    save_peer(doc)
    return {"name": doc.name, "address": address, "revision": advance_revision(network)}


@frappe.whitelist(methods=["POST"])
def set_hub(name):
    require_role("VPN Manager")
    network = get_locked_network()
    if network.hub and network.hub != name:
        raise frappe.ValidationError(
            "Hub replacement requires explicit reprovisioning; failover is out of scope"
        )
    peer = frappe.get_doc("VPN Peer", name, for_update=True)
    if peer.kind != "Service" or not is_peer_active(peer) or not peer.endpoint:
        raise frappe.ValidationError("Hub must be an active service with a reachable UDP endpoint")
    if not network.hub:
        frappe.db.set_value("VPN Network", "default", "hub", name)
        advance_revision(network)
    return {"hub": name}


@frappe.whitelist(methods=["POST"])
def update_peer(name, enabled=None, public_key=None, endpoint=None):
    manager = "VPN Manager" in frappe.get_roles()
    if not manager:
        require_role("VPN Engineer")
    network = get_locked_network()
    peer = frappe.get_doc("VPN Peer", name, for_update=True)
    if not manager and (peer.kind != "Device" or peer.user != frappe.session.user):
        raise frappe.PermissionError("Not your device")
    if enabled is not None:
        if type(enabled) not in (bool, int, str) or enabled not in (0, 1, "0", "1"):
            raise frappe.ValidationError("enabled must be 0 or 1")
        if name == network.hub and not int(enabled):
            raise frappe.ValidationError("The configured hub must remain enabled")
        peer.enabled = int(enabled)
    if public_key is not None:
        peer.public_key = validate_input(validation.public_key, public_key)
    if endpoint is not None:
        if peer.kind != "Service":
            raise frappe.ValidationError("Device endpoints are learned by WireGuard")
        peer.endpoint = validate_input(validation.endpoint, endpoint)
    save_peer(peer)
    return {"revision": advance_revision(network)}


def get_owned_peer(name):
    peer = frappe.get_doc("VPN Peer", name, for_update=True)
    if peer.user != frappe.session.user:
        raise frappe.PermissionError("This credential belongs to another peer")
    require_role("VPN Host" if peer.kind == "Service" else "VPN Engineer")
    return peer


@frappe.whitelist(methods=["GET"])
def configuration(name):
    if not {"VPN Host", "VPN Engineer"}.intersection(frappe.get_roles()):
        raise frappe.PermissionError("VPN identity required")
    network = get_locked_network()
    peer = get_owned_peer(name)
    peers = get_locked_peers()
    hub, members = get_active_membership(network, peers)
    return build_configuration(peer, network, hub, members)


def get_active_membership(network, peers):
    members = [peer for peer in peers if is_peer_active(peer)]
    hub = next((peer for peer in members if peer.name == network.hub), None)
    if not hub:
        raise frappe.ValidationError("Select an active hub before configuring the network")
    return hub, members


def build_configuration(peer, network, hub, members):
    identity = {"name": peer.name, "public_key": peer.public_key, "address": peer.address}
    return topology.build_configuration(
        identity,
        hub,
        members,
        network.subnet,
        network.revision,
        any(member.name == peer.name for member in members),
    )


@frappe.whitelist(methods=["POST"])
def report(name, revision, success):
    require_role("VPN Host")
    if type(revision) is not int or revision < 1:
        raise frappe.ValidationError("Expected a positive integer revision")
    if type(success) is not bool:
        raise frappe.ValidationError("Expected boolean success")
    network = get_locked_network()
    peer = get_owned_peer(name)
    if peer.kind != "Service":
        raise frappe.PermissionError("Only service hosts report application")
    if revision != network.revision:
        raise frappe.ValidationError("Outdated application report; fetch current configuration")
    peers = get_locked_peers()
    hub, members = get_active_membership(network, peers)
    digest = topology.desired_digest(build_configuration(peer, network, hub, members))
    frappe.db.set_value(
        "VPN Peer",
        name,
        {
            "reported_revision": revision,
            "apply_success": int(success),
            "reported_digest": digest if success else None,
            "reported_at": frappe.utils.now_datetime(),
        },
        update_modified=False,
    )
    return {"accepted": True}


@frappe.whitelist(methods=["GET"])
def status():
    require_role("VPN Manager")
    network = get_locked_network()
    if not network.hub:
        return {
            "revision": network.revision,
            "hub": None,
            "hub_current": False,
            "hosts": [],
            "all_current": False,
        }
    peers = get_locked_peers()
    hub, members = get_active_membership(network, peers)
    active_names = {member.name for member in members}
    fields = ("name", "enabled", "reported_revision", "apply_success", "reported_at")
    hosts = []
    for peer in peers:
        if peer.kind != "Service":
            continue
        host = frappe._dict({field: peer[field] for field in fields})
        host["required"] = peer.name in active_names
        digest = topology.desired_digest(build_configuration(peer, network, hub, members))
        host["current"] = bool(peer.apply_success and peer.reported_digest == digest)
        hosts.append(host)
    hub_current = next(host.current for host in hosts if host.name == network.hub)
    return {
        "revision": network.revision,
        "hub": network.hub,
        "hub_current": hub_current,
        "hosts": hosts,
        "all_current": all(host.current for host in hosts if host.required),
    }


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
    network = get_locked_network()
    peers = get_locked_peers()
    hub_user = next((peer.user for peer in peers if peer.name == network.hub), None)
    if hub_user == doc.name and (
        method == "on_trash" or not doc.enabled or "VPN Host" not in {row.role for row in doc.roles}
    ):
        raise frappe.ValidationError("The hub account must remain enabled with VPN Host authority")
    if any(peer.user == doc.name and peer.enabled for peer in peers):
        advance_revision(network)
