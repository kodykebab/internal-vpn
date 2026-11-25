frappe.listview_settings["VPN Server"] = {
	add_fields: ["status", "enabled"],
	get_indicator(doc) {
		if (!doc.enabled) return [__("Disabled"), "gray", "enabled,=,0"];
		const color = { Current: "green", Pending: "orange", Failed: "red", Stale: "red" }[doc.status];
		return [__(doc.status), color, `status,=,${doc.status}`];
	},
};
