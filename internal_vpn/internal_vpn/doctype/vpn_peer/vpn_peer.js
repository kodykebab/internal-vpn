frappe.ui.form.on("VPN Peer", {
	refresh(frm) {
		frm.disable_save();
		if (frm.is_new()) return;
		const owner = frm.doc.user === frappe.session.user;
		const device_owner = owner && frm.doc.kind === "Device";
		const manager = frappe.user.has_role("VPN Manager");
		const run = async (method, args, message, after = () => frm.reload_doc()) => {
			const result = await call_vpn_method(frm, method, args);
			if (!result) return;
			frappe.show_alert({ message, indicator: "green" }, 5);
			after(result);
		};

		if (!frm.doc.enabled) {
			frm.set_intro(__("Disabled. Release it to free {0} once the hub has applied the removal.", [frm.doc.address]), "orange");
		}
		if (device_owner) frm.add_custom_button(__("Configuration"), () => show_configuration(frm));
		if (!manager && !device_owner) return;

		if (frm.doc.enabled) {
			frm.add_custom_button(
				__("Disable"),
				() =>
					frappe.confirm(
						__("Disable {0}? It loses access once the hub applies the change.", [frm.doc.name]),
						() => run("set_enabled", { enabled: 0 }, __("Peer disabled")),
					),
				__("Peer"),
			);
		} else {
			frm.add_custom_button(
				__("Enable"),
				() => run("set_enabled", { enabled: 1 }, __("Peer enabled")),
				__("Peer"),
			);
			frm.add_custom_button(
				__("Release"),
				() =>
					frappe.confirm(__("Delete {0} and free {1}?", [frm.doc.name, frm.doc.address]), () =>
						run("release", {}, __("Address {0} freed", [frm.doc.address]), () => frappe.set_route("List", "VPN Peer"))),
				__("Peer"),
			);
		}
		frm.add_custom_button(
			__("Rotate Key"),
			() =>
				frappe.prompt(
					{ fieldname: "public_key", label: __("New WireGuard Public Key"), fieldtype: "Data", reqd: 1 },
					(values) => run("rotate_key", values, __("Key rotated")),
					__("Rotate Key"),
				),
			__("Peer"),
		);
		if (manager && frm.doc.kind === "Service") {
			frm.add_custom_button(
				__("Set Endpoint"),
				() =>
					frappe.prompt(
						{ fieldname: "endpoint", label: __("UDP Endpoint"), fieldtype: "Data", reqd: 1, default: frm.doc.endpoint },
						(values) => run("set_endpoint", values, __("Endpoint updated")),
						__("Set Endpoint"),
					),
				__("Peer"),
			);
		}
	},
});

// Frappe has already shown the server's error, so a refused call returns null and the caller stops.
async function call_vpn_method(frm, method, args = {}, type = "POST") {
	try {
		return (await frm.call({ doc: frm.doc, method, args, type, freeze: true })).message ?? {};
	} catch {
		return null;
	}
}

async function show_configuration(frm) {
	const snapshot = await call_vpn_method(frm, "get_configuration", {}, "GET");
	if (!snapshot) return;
	const lines = ["[Interface]", "PrivateKey = <your private key>", `Address = ${snapshot.address}/${snapshot.subnet.split("/")[1]}`];
	for (const peer of snapshot.peers) {
		lines.push("", "[Peer]", `PublicKey = ${peer.public_key}`, `AllowedIPs = ${peer.allowed_ips}`);
		lines.push(`Endpoint = ${peer.endpoint}`, "PersistentKeepalive = 25");
	}
	const configuration = lines.join("\n");
	const dialog = new frappe.ui.Dialog({
		title: __("WireGuard Configuration"),
		fields: [
			{ fieldname: "configuration", fieldtype: "Code", read_only: 1, default: configuration },
			{
				fieldtype: "HTML",
				options: `<p class="text-muted small">${
					snapshot.peers.length
						? __("Replace the private key placeholder with the key you generated. It never leaves your device.")
						: __("No peers: this device is disabled or you no longer have the VPN Engineer role.")
				}</p>`,
			},
		],
		primary_action_label: __("Copy"),
		primary_action() {
			frappe.utils.copy_to_clipboard(configuration);
			dialog.hide();
		},
	});
	dialog.show();
}
