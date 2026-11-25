frappe.ui.form.on("VPN Server", {
	refresh(frm) {
		frm.set_intro(
			frm.doc.enabled || frm.is_new() ? "" : __("Disabled. Delete it after the hub applies the change."),
			"orange"
		);
	},
});
