frappe.ui.form.on("VPN Device", {
	refresh(frm) {
		frm.set_intro(
			frm.doc.enabled || frm.is_new() ? "" : __("Disabled. Delete it after the hub applies the change."),
			"orange"
		);
		if (!frm.is_new()) frm.add_custom_button(__("Configuration"), () => show_configuration(frm));
	},
	before_save(frm) {
		frm.vpn_was_new = frm.is_new();
	},
	after_save(frm) {
		if (frm.vpn_was_new) show_configuration(frm);
	},
});

function show_configuration(frm) {
	frm.call({
		method: "get_configuration",
		doc: frm.doc,
		type: "GET",
		callback: ({ message: snapshot }) => {
			const lines = [
				"[Interface]",
				"PrivateKey = <contents of vpn.key>",
				`Address = ${snapshot.address}/${snapshot.subnet.split("/")[1]}`,
			];
			for (const peer of snapshot.peers) {
				lines.push(
					"",
					"[Peer]",
					`PublicKey = ${peer.public_key}`,
					`AllowedIPs = ${peer.allowed_ips}`,
					`Endpoint = ${peer.endpoint}`,
					"PersistentKeepalive = 25"
				);
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
								? __("Replace the placeholder with the contents of vpn.key, then import this into the WireGuard app.")
								: __("This device is disabled.")
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
		},
	});
}
