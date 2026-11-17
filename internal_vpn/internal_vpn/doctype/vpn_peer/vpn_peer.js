frappe.ui.form.on("VPN Peer", {
	refresh(frm) {
		new VPNPeerForm(frm).refresh();
	},
});

class VPNPeerForm {
	constructor(frm) {
		this.frm = frm;
	}

	refresh() {
		const frm = this.frm;
		frm.disable_save();
		if (frm.is_new()) return;
		// Frappe’s read-only Check formatter draws a tick without setting checked.
		for (const field of ["enabled", "apply_success"]) {
			frm.fields_dict[field].$wrapper.find('input[type="checkbox"]').prop("checked", !!frm.doc[field]);
		}
		const device_owner = frm.doc.user === frappe.session.user && frm.doc.kind === "Device";
		const manager = frappe.user.has_role("VPN Manager");
		frm.set_intro(frm.doc.enabled ? "" : __("Disabled. Release it after the hub applies removal."), "orange");
		if (device_owner) {
			frm.add_custom_button(__("Configuration"), () => this.configuration());
			if (frappe.flags.vpn_show_configuration === frm.doc.name) {
				frappe.flags.vpn_show_configuration = null;
				this.configuration();
			}
		}
		if (!manager && !device_owner) return;

		frm.add_custom_button(
			frm.doc.enabled ? __("Disable") : __("Enable"),
			() => this.set_enabled(),
			__("Peer")
		);
		if (!frm.doc.enabled) frm.add_custom_button(__("Release"), () => this.release(), __("Peer"));
		frm.add_custom_button(__("Rotate Key"), () => this.rotate_key(), __("Peer"));
		if (manager && frm.doc.kind === "Service")
			frappe.db.get_value("VPN Network", "default", "hub").then(({ message }) => {
				if (!message.hub || message.hub === frm.doc.name)
					frm.add_custom_button(__("Set Endpoint"), () => this.set_endpoint(), __("Peer"));
			});
	}

	call(method, args = {}, callback = () => this.frm.reload_doc(), type = "POST") {
		frappe.call({
			method: "frappe.handler.run_doc_method",
			args: { dt: this.frm.doctype, dn: this.frm.doc.name, method, args },
			type,
			freeze: true,
			callback: (response) => callback(response.message),
		});
	}

	configuration() {
		this.call("get_configuration", {}, (snapshot) => this.show_configuration(snapshot), "GET");
	}

	set_enabled() {
		if (!this.frm.doc.enabled) return this.call("set_enabled", { enabled: 1 });
		frappe.confirm(__("Disable {0}? Access ends when the hub applies the change.", [this.frm.doc.label || this.frm.doc.name]), () =>
			this.call("set_enabled", { enabled: 0 })
		);
	}

	release() {
		frappe.confirm(__("Delete {0} and free {1}?", [this.frm.doc.label || this.frm.doc.name, this.frm.doc.address]), () =>
			this.call("release", {}, () => frappe.set_route("List", "VPN Peer"))
		);
	}

	rotate_key() {
		frappe.prompt(
			{ fieldname: "public_key", label: __("New WireGuard Public Key"), fieldtype: "Data", reqd: 1 },
			(values) => this.call("rotate_key", values),
			__("Rotate Key")
		);
	}

	set_endpoint() {
		frappe.prompt(
			{
				fieldname: "endpoint",
				label: __("UDP Endpoint"),
				fieldtype: "Data",
				reqd: 1,
				default: this.frm.doc.endpoint,
			},
			(values) => this.call("set_endpoint", values),
			__("Set Endpoint")
		);
	}

	show_configuration(snapshot) {
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
	}
}
