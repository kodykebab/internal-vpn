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
		else
			frappe.db.get_value("VPN Server", frm.doc.hub, "status").then(({ message }) => {
				if (["Failed", "Stale"].includes(message?.status))
					frm.set_intro(__("The hub is {0}. See the VPN Server list.", [__(message.status)]), "red");
			});
		frm.set_query("hub", () => ({ filters: { enabled: 1 } }));

		frm.add_custom_button(__("Invite Engineer"), () => this.invite_engineer());
		frm.add_custom_button(__("Servers"), () => frappe.set_route("List", "VPN Server"));
	}

	invite_engineer() {
		frappe.prompt(
			{ fieldname: "emails", label: __("Emails"), fieldtype: "Small Text", reqd: 1 },
			({ emails }) =>
				frappe.call({
					method: "frappe.core.api.user_invitation.invite_by_email",
					args: {
						emails,
						roles: ["VPN Engineer"],
						redirect_to_path: "/desk/vpn-device",
						app_name: "internal_vpn",
					},
					freeze: true,
					callback: ({ message }) =>
						frappe.msgprint(
							[
								[__("Invited"), message.invited_emails],
								[__("Already invited"), message.pending_invite_emails],
								[__("Already accepted"), message.accepted_invite_emails],
								[__("Disabled users"), message.disabled_user_emails],
							]
								.filter(([, emails]) => emails.length)
								.map(([label, emails]) => `${label}: ${frappe.utils.escape_html(emails.join(", "))}`)
								.join("<br>"),
							__("Invite Engineer")
						),
				}),
			__("Invite Engineer")
		);
	}
}
