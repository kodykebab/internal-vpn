frappe.listview_settings["VPN Device"] = {
	add_fields: ["enabled", "last_handshake"],
	get_indicator(doc) {
		if (!doc.enabled) return [__("Disabled"), "gray", "enabled,=,0"];
		if (!doc.last_handshake) return [__("Never connected"), "orange", "last_handshake,is,not set"];
		// WireGuard rekeys an active tunnel every two minutes.
		const minutes = moment(frappe.datetime.system_datetime()).diff(moment(doc.last_handshake), "minutes");
		if (minutes < 3) return [__("Connected"), "green", "enabled,=,1"];
		return [__("Seen {0} ago", [frappe.datetime.prettyDate(doc.last_handshake, true)]), "gray", "enabled,=,1"];
	},
};
