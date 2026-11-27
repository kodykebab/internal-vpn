frappe.ui.form.on("VPN Server", {
	refresh(frm) {
		frm.set_intro("");
		if (!frm.doc.enabled && !frm.is_new())
			frm.set_intro(__("Disabled. Delete it after the hub applies the change."), "orange");
		const enrollment = frm.doc.__onload?.enrollment;
		if (enrollment?.expired) {
			frm.set_intro(__("The enrollment window has closed. Use New Enrollment to open another."), "orange");
		} else if (enrollment) {
			frm.set_intro(
				__("Run this as root on the server before {0}. It works once.", [
					frappe.datetime.str_to_user(enrollment.expires),
				]) + `<pre class="mt-2 mb-0 small">${frappe.utils.escape_html(enrollment.command)}</pre>`,
				"blue"
			);
			frm.add_custom_button(__("Copy Enrollment Command"), () =>
				frappe.utils.copy_to_clipboard(enrollment.command)
			);
		}
		if (!frm.is_new() && frm.perm[0]?.write)
			frm.add_custom_button(__("New Enrollment"), () =>
				frappe.confirm(
					__("Remove {0}'s key and token, and open a new enrollment window?", [frm.doc.label]),
					() => frm.call("new_enrollment").then(() => frm.reload_doc())
				)
			);
	},
});
