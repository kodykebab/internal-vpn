frappe.ui.form.on("VPN Network", {
	refresh(frm) {
		new VPNNetworkForm(frm).refresh();
	},
});

class VPNNetworkForm {
	constructor(frm) {
		this.frm = frm;
	}

	refresh() {
		const frm = this.frm;
		frm.disable_save();
		if (frm.is_new()) return;
		frm.set_intro("");
		if (!frm.doc.subnet) frm.set_intro(__("Initialize the subnet before registering peers."), "orange");
		else if (!frm.doc.hub) frm.set_intro(__("Set the hub before hosts and devices can connect."), "orange");
		if (frm.doc.hub_alert) frm.set_intro(__(frm.doc.hub_alert), "red");

		if (frappe.user.has_role("VPN Engineer")) {
			frm.add_custom_button(__("Register Device"), () => this.register_device());
			frm.add_custom_button(__("My Devices"), () => frappe.set_route("List", "VPN Peer"));
		}
		if (!frappe.user.has_role("VPN Manager")) return;
		frm.add_custom_button(__("Add Engineer"), () => this.add_engineer(), __("Network"));
		if (!frm.doc.subnet) frm.add_custom_button(__("Initialize"), () => this.initialize(), __("Network"));
		frm.add_custom_button(__("Register Service"), () => this.register_service(), __("Network"));
		if (!frm.doc.hub) frm.add_custom_button(__("Set Hub"), () => this.set_hub(), __("Network"));
		frm.add_custom_button(__("Status"), () =>
			this.call("get_status", {}, (status) => this.show_status(status), "GET")
		);
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

	initialize() {
		frappe.prompt(
			{
				fieldname: "subnet",
				label: __("Subnet"),
				fieldtype: "Data",
				reqd: 1,
				description: __("Inside 100.64.0.0/10"),
			},
			(values) => this.call("initialize", values),
			__("Initialize")
		);
	}

	add_engineer() {
		frappe.prompt(
			[
				{ fieldname: "email", label: __("Email"), fieldtype: "Data", options: "Email", reqd: 1 },
				{ fieldname: "first_name", label: __("First Name"), fieldtype: "Data" },
			],
			(values) => this.call("add_engineer", values, (result) => this.show_credentials(result)),
			__("Add Engineer")
		);
	}

	show_credentials({ user, password }) {
		if (!password) {
			frappe.show_alert({ message: __("{0} can now register devices", [user]), indicator: "green" });
			return;
		}
		const text = `${user}\n${password}`;
		const dialog = new frappe.ui.Dialog({
			title: __("Initial Password"),
			fields: [
				{ fieldname: "credentials", fieldtype: "Code", read_only: 1, default: text },
				{
					fieldtype: "HTML",
					options: `<p class="text-muted small">${__(
						"Shown once. Hand it to the engineer privately; they can change it under My Settings."
					)}</p>`,
				},
			],
			primary_action_label: __("Copy"),
			primary_action() {
				frappe.utils.copy_to_clipboard(text);
				dialog.hide();
			},
		});
		dialog.show();
	}

	register_device() {
		frappe.prompt(
			[
				{
					fieldname: "label",
					label: __("Device Name"),
					fieldtype: "Data",
					reqd: 1,
					description: __("For example, work laptop"),
				},
				{
					fieldname: "public_key",
					label: __("WireGuard Public Key"),
					fieldtype: "Data",
					reqd: 1,
					description: __("On the device, run: wg genkey | tee vpn.key | wg pubkey"),
				},
			],
			(values) =>
				this.call("register_device", values, (peer) => {
					// The peer form opens its configuration once on arrival.
					frappe.flags.vpn_show_configuration = peer.name;
					frappe.set_route("Form", "VPN Peer", peer.name);
				}),
			__("Register Device")
		);
	}

	register_service() {
		frappe.prompt(
			[
				{ fieldname: "label", label: __("Service Name"), fieldtype: "Data", reqd: 1 },
				{ fieldname: "user", label: __("Host User"), fieldtype: "Link", options: "User", reqd: 1 },
				{ fieldname: "public_key", label: __("WireGuard Public Key"), fieldtype: "Data", reqd: 1 },
				{
					fieldname: "endpoint",
					label: __("UDP Endpoint"),
					fieldtype: "Data",
					description: __("Required for the hub"),
				},
			],
			(values) =>
				this.call("register_service", values, (peer) => frappe.set_route("Form", "VPN Peer", peer.name)),
			__("Register Service")
		);
	}

	set_hub() {
		frappe.prompt(
			{
				fieldname: "peer",
				label: __("Service Peer"),
				fieldtype: "Link",
				options: "VPN Peer",
				reqd: 1,
				get_query: () => ({ filters: { kind: "Service", enabled: 1 } }),
			},
			(values) => this.call("set_hub", values),
			__("Set Hub")
		);
	}

	show_status(status) {
		const rows = status.hosts.map(
			(host) => `<tr>
			<td>${frappe.utils.get_form_link("VPN Peer", host.name, true, frappe.utils.escape_html(host.address))}</td>
			<td>${frappe.utils.escape_html(host.user)}</td>
			<td>${host.required ? __("Yes") : __("No")}</td>
			<td><span class="indicator-pill ${
				host.current ? "green" : host.reported_at && !host.apply_success ? "red" : "orange"
			}">${
				host.current ? __("Current") : host.reported_at && !host.apply_success ? __("Failed") : __("Pending")
			}</span></td>
			<td>${host.reported_revision ?? ""}</td>
			<td>${host.reported_at ? frappe.datetime.comment_when(host.reported_at) : ""}</td>
		</tr>`
		);
		new frappe.ui.Dialog({
			title: __("Revision {0}: {1}", [
				status.revision,
				status.all_current ? __("all hosts current") : __("hosts pending"),
			]),
			size: "large",
			fields: [
				{
					fieldtype: "HTML",
					options: `<table class="table table-bordered small">
				<tr><th>${__("Host")}</th><th>${__("Owner")}</th><th>${__("Active")}</th><th>${__("Applied")}</th><th>${__(
						"Revision"
					)}</th><th>${__("Reported")}</th></tr>
				${rows.join("")}
			</table>`,
				},
			],
		}).show();
	}
}
