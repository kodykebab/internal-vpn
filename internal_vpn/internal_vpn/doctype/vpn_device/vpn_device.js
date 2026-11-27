frappe.ui.form.on("VPN Device", {
	refresh(frm) {
		frm.set_intro(
			frm.doc.enabled || frm.is_new() ? "" : __("Disabled. Delete it after the hub applies the change."),
			"orange"
		);
		if (!frm.is_new()) frm.add_custom_button(__("New Configuration"), () => new_configuration(frm));
	},
	async before_save(frm) {
		if (!frm.doc.public_key) {
			const keys = await generate_keys();
			frm.vpn_private_key = keys.private_key;
			frm.doc.public_key = keys.public_key;
		}
		frm.vpn_download = frm.is_new() || Boolean(frm.vpn_private_key);
	},
	after_save(frm) {
		if (frm.vpn_download) download_configuration(frm, frm.vpn_private_key);
		frm.vpn_private_key = null;
		frm.vpn_download = false;
	},
});

// The private key exists only in this page until the file is downloaded; the app never sees it.
async function generate_keys() {
	await frappe.require("/assets/internal_vpn/js/tweetnacl-1.0.3/nacl.min.js");
	const secret = nacl.randomBytes(32);
	secret[0] &= 248;
	secret[31] = (secret[31] & 127) | 64;
	const base64 = (bytes) => btoa(String.fromCharCode(...bytes));
	return { private_key: base64(secret), public_key: base64(nacl.scalarMult.base(secret)) };
}

function new_configuration(frm) {
	frappe.confirm(
		__("Make new keys for {0}? Its current configuration stops working once the hub applies the change.", [
			frm.doc.label,
		]),
		async () => {
			const keys = await generate_keys();
			frm.vpn_private_key = keys.private_key;
			await frm.set_value("public_key", keys.public_key);
			frm.save();
		}
	);
}

function download_configuration(frm, private_key) {
	const snapshot = frm.doc.__onload?.configuration;
	if (!snapshot?.peers.length) {
		frappe.msgprint(__("This device is not active on the network yet, so there is no configuration to download."));
		return;
	}
	const [hub] = snapshot.peers;
	const text = [
		"[Interface]",
		`PrivateKey = ${private_key || "<private key of this device>"}`,
		`Address = ${snapshot.address}/${snapshot.subnet.split("/")[1]}`,
		"",
		"[Peer]",
		`PublicKey = ${hub.public_key}`,
		`AllowedIPs = ${hub.allowed_ips}`,
		`Endpoint = ${hub.endpoint}`,
		"PersistentKeepalive = 25",
		"",
	].join("\n");
	// WireGuard names a tunnel after its file: at most 15 of [A-Za-z0-9_=+.-].
	const name = `ivpn-${frm.doc.label.toLowerCase().replace(/[^a-z0-9_=+.-]+/g, "-")}`.slice(0, 15).replace(/-+$/, "");
	const link = document.createElement("a");
	link.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
	link.download = `${name}.conf`;
	link.click();
	setTimeout(() => URL.revokeObjectURL(link.href), 1000);
	frappe.show_alert({ message: __("Import {0} into the WireGuard app.", [link.download]), indicator: "green" });
}
