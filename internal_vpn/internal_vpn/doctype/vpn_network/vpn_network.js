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
		frm.set_intro("");
		if (!frm.doc.subnet) frm.set_intro(__("Set the subnet before adding servers and devices."), "orange");
		else if (!frm.doc.hub) frm.set_intro(__("Set the hub before hosts and devices can connect."), "orange");
		if (frm.doc.hub_alert) frm.set_intro(__(frm.doc.hub_alert), "red");
		frm.set_query("hub", () => ({ filters: { enabled: 1 } }));

		frm.add_custom_button(__("Add Engineer"), () => this.add_engineer());
		frm.add_custom_button(__("Status"), () =>
			frm.call({ method: "get_status", doc: frm.doc, type: "GET", callback: (r) => this.show_status(r.message) })
		);
	}

	add_engineer() {
		frappe.prompt(
			[
				{ fieldname: "email", label: __("Email"), fieldtype: "Data", options: "Email", reqd: 1 },
				{ fieldname: "first_name", label: __("First Name"), fieldtype: "Data" },
			],
			(values) => this.frm.call("add_engineer", values, (r) => this.show_credentials(r.message)),
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

	show_status(status) {
		// A stale report outranks the applied state: the host may have stopped running.
		const state = (host) =>
			host.stale
				? ["red", __("Stale")]
				: host.current
					? ["green", __("Current")]
					: host.reported_at && !host.apply_success
						? ["red", __("Failed")]
						: ["orange", __("Pending")];
		const rows = status.hosts.map(
			(host) => `<tr>
			<td>${frappe.utils.get_form_link("VPN Server", host.name, true, frappe.utils.escape_html(host.label))}</td>
			<td>${frappe.utils.escape_html(host.address)}</td>
			<td>${frappe.utils.escape_html(host.user)}</td>
			<td>${host.required ? __("Yes") : __("No")}</td>
			<td><span class="indicator-pill ${state(host)[0]}">${state(host)[1]}</span></td>
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
				<tr><th>${__("Server")}</th><th>${__("Address")}</th><th>${__("Host User")}</th><th>${__(
						"Active"
					)}</th><th>${__("Applied")}</th><th>${__("Revision")}</th><th>${__("Reported")}</th></tr>
				${rows.join("")}
			</table>`,
				},
			],
		}).show();
	}
}
