frappe.ui.form.on("VPN Network", {
	refresh(frm) {
		frm.disable_save();
		const manager = frappe.user.has_role("VPN Manager");
		const run = async (method, args, message, after = () => frm.reload_doc()) => {
			const result = await call_vpn_method(frm, method, args);
			if (!result) return;
			frappe.show_alert({ message, indicator: "green" }, 5);
			after(result);
		};
		const open_peer = (result) => frappe.set_route("Form", "VPN Peer", result.name);

		if (!frm.doc.subnet) frm.set_intro(__("Initialize the subnet before registering peers."), "orange");
		else if (!frm.doc.hub) frm.set_intro(__("Set the hub before hosts and devices can connect."), "orange");

		if (frappe.user.has_role("VPN Engineer")) {
			frm.add_custom_button(__("Register Device"), () =>
				frappe.prompt(
					{ fieldname: "public_key", label: __("WireGuard Public Key"), fieldtype: "Data", reqd: 1 },
					(values) => run("register_device", values, __("Device registered"), open_peer),
					__("Register Device"),
				),
			);
		}
		if (!manager) return;

		if (!frm.doc.subnet) {
			frm.add_custom_button(
				__("Initialize"),
				() =>
					frappe.prompt(
						{ fieldname: "subnet", label: __("Subnet"), fieldtype: "Data", reqd: 1, description: __("Inside 100.64.0.0/10") },
						(values) => run("initialize", values, __("Subnet set")),
						__("Initialize"),
					),
				__("Network"),
			);
		}
		frm.add_custom_button(
			__("Register Service"),
			() =>
				frappe.prompt(
					[
						{ fieldname: "user", label: __("Host User"), fieldtype: "Link", options: "User", reqd: 1 },
						{ fieldname: "public_key", label: __("WireGuard Public Key"), fieldtype: "Data", reqd: 1 },
						{ fieldname: "endpoint", label: __("UDP Endpoint"), fieldtype: "Data", description: __("Required for the hub") },
					],
					(values) => run("register_service", values, __("Service registered"), open_peer),
					__("Register Service"),
				),
			__("Network"),
		);
		if (!frm.doc.hub) {
			frm.add_custom_button(
				__("Set Hub"),
				() =>
					frappe.prompt(
						{ fieldname: "peer", label: __("Service Peer"), fieldtype: "Link", options: "VPN Peer", reqd: 1 },
						(values) => run("set_hub", values, __("Hub set")),
						__("Set Hub"),
					),
				__("Network"),
			);
		}
		frm.add_custom_button(__("Status"), async () => {
			const status = await call_vpn_method(frm, "get_status", {}, "GET");
			if (status) show_status(status);
		});
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

function show_status(status) {
	const pill = (ok, yes, no) => `<span class="indicator-pill ${ok ? "green" : "orange"}">${ok ? yes : no}</span>`;
	const rows = status.hosts.map(
		(host) => `<tr>
			<td>${frappe.utils.get_form_link("VPN Peer", host.name, true, frappe.utils.escape_html(host.address))}</td>
			<td>${frappe.utils.escape_html(host.user)}</td>
			<td>${host.required ? __("Yes") : __("No")}</td>
			<td>${pill(host.current, __("Current"), __("Pending"))}</td>
			<td>${host.reported_revision ?? ""}</td>
			<td>${host.reported_at ? frappe.datetime.comment_when(host.reported_at) : ""}</td>
		</tr>`,
	);
	new frappe.ui.Dialog({
		title: __("Revision {0}: {1}", [status.revision, status.all_current ? __("all hosts current") : __("hosts pending")]),
		size: "large",
		fields: [
			{
				fieldtype: "HTML",
				options: `<table class="table table-bordered small">
					<tr><th>${__("Host")}</th><th>${__("Owner")}</th><th>${__("Active")}</th><th>${__("Applied")}</th><th>${__("Revision")}</th><th>${__("Reported")}</th></tr>
					${rows.join("")}
				</table>`,
			},
		],
	}).show();
}
