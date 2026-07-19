# Generate selected Bluetooth SIG Assigned Numbers test oracles.
# Input is the official Assigned Numbers HTML snapshot.

BEGIN {
	profile_uuid_names = \
	    "Generic Access service|Generic Attribute service|Immediate Alert service|Blood Pressure service|Glucose service|Human Interface Device service|Battery service|Device Information service|Heart Rate service|Health Thermometer service|" \
	    "Device Name|Appearance|Service Changed|Central Address Resolution|Client Supported Features|Database Hash|Server Supported Features|Glucose Measurement|" \
	    "Battery Level|Manufacturer Name String|Model Number String|Serial Number String|Firmware Revision String|Hardware Revision String|Software Revision String|System ID|PnP ID|" \
	    "Heart Rate Measurement|Body Sensor Location|Temperature Measurement|HID Information|Report Map|HID Control Point|Report"
	profile_uuid_count = split(profile_uuid_names, profile_uuid_name, "|")
	profile_uuid_symbol["Generic Access service"] = "GENERIC_ACCESS_SERVICE"
	profile_uuid_expect["Generic Access service"] = "0x1800"
	profile_uuid_symbol["Generic Attribute service"] = "GENERIC_ATTRIBUTE_SERVICE"
	profile_uuid_expect["Generic Attribute service"] = "0x1801"
	profile_uuid_symbol["Immediate Alert service"] = "IMMEDIATE_ALERT_SERVICE"
	profile_uuid_expect["Immediate Alert service"] = "0x1802"
	profile_uuid_symbol["Blood Pressure service"] = "BLOOD_PRESSURE_SERVICE"
	profile_uuid_expect["Blood Pressure service"] = "0x1810"
	profile_uuid_symbol["Glucose service"] = "GLUCOSE_SERVICE"
	profile_uuid_expect["Glucose service"] = "0x1808"
	profile_uuid_symbol["Human Interface Device service"] = "HID_SERVICE"
	profile_uuid_expect["Human Interface Device service"] = "0x1812"
	profile_uuid_symbol["Battery service"] = "BATTERY_SERVICE"
	profile_uuid_expect["Battery service"] = "0x180f"
	profile_uuid_symbol["Device Information service"] = "DEVICE_INFORMATION_SERVICE"
	profile_uuid_expect["Device Information service"] = "0x180a"
	profile_uuid_symbol["Heart Rate service"] = "HEART_RATE_SERVICE"
	profile_uuid_expect["Heart Rate service"] = "0x180d"
	profile_uuid_symbol["Health Thermometer service"] = "HEALTH_THERMOMETER_SERVICE"
	profile_uuid_expect["Health Thermometer service"] = "0x1809"
	profile_uuid_symbol["Device Name"] = "DEVICE_NAME"
	profile_uuid_expect["Device Name"] = "0x2a00"
	profile_uuid_symbol["Appearance"] = "APPEARANCE"
	profile_uuid_expect["Appearance"] = "0x2a01"
	profile_uuid_symbol["Service Changed"] = "SERVICE_CHANGED"
	profile_uuid_expect["Service Changed"] = "0x2a05"
	profile_uuid_symbol["Central Address Resolution"] = "CENTRAL_ADDRESS_RESOLUTION"
	profile_uuid_expect["Central Address Resolution"] = "0x2aa6"
	profile_uuid_symbol["Client Supported Features"] = "CLIENT_SUPPORTED_FEATURES"
	profile_uuid_expect["Client Supported Features"] = "0x2b29"
	profile_uuid_symbol["Database Hash"] = "DATABASE_HASH"
	profile_uuid_expect["Database Hash"] = "0x2b2a"
	profile_uuid_symbol["Server Supported Features"] = "SERVER_SUPPORTED_FEATURES"
	profile_uuid_expect["Server Supported Features"] = "0x2b3a"
	profile_uuid_symbol["Glucose Measurement"] = "GLUCOSE_MEASUREMENT"
	profile_uuid_expect["Glucose Measurement"] = "0x2a18"
	profile_uuid_symbol["Battery Level"] = "BATTERY_LEVEL"
	profile_uuid_expect["Battery Level"] = "0x2a19"
	profile_uuid_symbol["Manufacturer Name String"] = "MANUFACTURER_NAME_STRING"
	profile_uuid_expect["Manufacturer Name String"] = "0x2a29"
	profile_uuid_symbol["Model Number String"] = "MODEL_NUMBER_STRING"
	profile_uuid_expect["Model Number String"] = "0x2a24"
	profile_uuid_symbol["Serial Number String"] = "SERIAL_NUMBER_STRING"
	profile_uuid_expect["Serial Number String"] = "0x2a25"
	profile_uuid_symbol["Firmware Revision String"] = "FIRMWARE_REVISION_STRING"
	profile_uuid_expect["Firmware Revision String"] = "0x2a26"
	profile_uuid_symbol["Hardware Revision String"] = "HARDWARE_REVISION_STRING"
	profile_uuid_expect["Hardware Revision String"] = "0x2a27"
	profile_uuid_symbol["Software Revision String"] = "SOFTWARE_REVISION_STRING"
	profile_uuid_expect["Software Revision String"] = "0x2a28"
	profile_uuid_symbol["System ID"] = "SYSTEM_ID"
	profile_uuid_expect["System ID"] = "0x2a23"
	profile_uuid_symbol["PnP ID"] = "PNP_ID"
	profile_uuid_expect["PnP ID"] = "0x2a50"
	profile_uuid_symbol["Heart Rate Measurement"] = "HEART_RATE_MEASUREMENT"
	profile_uuid_expect["Heart Rate Measurement"] = "0x2a37"
	profile_uuid_symbol["Body Sensor Location"] = "BODY_SENSOR_LOCATION"
	profile_uuid_expect["Body Sensor Location"] = "0x2a38"
	profile_uuid_symbol["Temperature Measurement"] = "TEMPERATURE_MEASUREMENT"
	profile_uuid_expect["Temperature Measurement"] = "0x2a1c"
	profile_uuid_symbol["HID Information"] = "HID_INFORMATION"
	profile_uuid_expect["HID Information"] = "0x2a4a"
	profile_uuid_symbol["Report Map"] = "REPORT_MAP"
	profile_uuid_expect["Report Map"] = "0x2a4b"
	profile_uuid_symbol["HID Control Point"] = "HID_CONTROL_POINT"
	profile_uuid_expect["HID Control Point"] = "0x2a4c"
	profile_uuid_symbol["Report"] = "REPORT"
	profile_uuid_expect["Report"] = "0x2a4d"
	lighting_key_text = \
	    "LIGHTNESS_GET LIGHTNESS_SET LIGHTNESS_SET_UNACK LIGHTNESS_STATUS " \
	    "LIGHTNESS_LINEAR_GET LIGHTNESS_LINEAR_SET LIGHTNESS_LINEAR_SET_UNACK LIGHTNESS_LINEAR_STATUS " \
	    "LIGHTNESS_LAST_GET LIGHTNESS_LAST_STATUS LIGHTNESS_DEFAULT_GET LIGHTNESS_DEFAULT_STATUS " \
	    "LIGHTNESS_RANGE_GET LIGHTNESS_RANGE_STATUS LIGHTNESS_DEFAULT_SET LIGHTNESS_DEFAULT_SET_UNACK " \
	    "LIGHTNESS_RANGE_SET LIGHTNESS_RANGE_SET_UNACK " \
	    "CTL_GET CTL_SET CTL_SET_UNACK CTL_STATUS CTL_TEMPERATURE_GET " \
	    "CTL_TEMPERATURE_RANGE_GET CTL_TEMPERATURE_RANGE_STATUS CTL_TEMPERATURE_SET " \
	    "CTL_TEMPERATURE_SET_UNACK CTL_TEMPERATURE_STATUS CTL_DEFAULT_GET CTL_DEFAULT_STATUS " \
	    "CTL_DEFAULT_SET CTL_DEFAULT_SET_UNACK CTL_TEMPERATURE_RANGE_SET CTL_TEMPERATURE_RANGE_SET_UNACK " \
	    "HSL_GET HSL_HUE_GET HSL_HUE_SET HSL_HUE_SET_UNACK HSL_HUE_STATUS " \
	    "HSL_SATURATION_GET HSL_SATURATION_SET HSL_SATURATION_SET_UNACK HSL_SATURATION_STATUS " \
	    "HSL_SET HSL_SET_UNACK HSL_STATUS HSL_TARGET_GET HSL_TARGET_STATUS " \
	    "HSL_DEFAULT_GET HSL_DEFAULT_STATUS HSL_RANGE_GET HSL_RANGE_STATUS " \
	    "HSL_DEFAULT_SET HSL_DEFAULT_SET_UNACK HSL_RANGE_SET HSL_RANGE_SET_UNACK " \
	    "XYL_GET XYL_SET XYL_SET_UNACK XYL_STATUS XYL_TARGET_GET XYL_TARGET_STATUS " \
	    "XYL_DEFAULT_GET XYL_DEFAULT_STATUS XYL_RANGE_GET XYL_RANGE_STATUS " \
	    "XYL_DEFAULT_SET XYL_DEFAULT_SET_UNACK XYL_RANGE_SET XYL_RANGE_SET_UNACK " \
	    "LC_MODE_GET LC_MODE_SET LC_MODE_SET_UNACK LC_MODE_STATUS LC_OM_GET LC_OM_SET " \
	    "LC_OM_SET_UNACK LC_OM_STATUS LC_LIGHT_ONOFF_GET LC_LIGHT_ONOFF_SET " \
	    "LC_LIGHT_ONOFF_SET_UNACK LC_LIGHT_ONOFF_STATUS LC_PROPERTY_GET"
	lighting_key_count = split(lighting_key_text, lighting_keys, " ")
	lighting_model_key_text = \
	    "LIGHT_LIGHTNESS_SRV LIGHT_LIGHTNESS_SETUP_SRV LIGHT_LIGHTNESS_CLI " \
	    "LIGHT_CTL_SRV LIGHT_CTL_SETUP_SRV LIGHT_CTL_CLI LIGHT_CTL_TEMP_SRV " \
	    "LIGHT_HSL_SRV LIGHT_HSL_SETUP_SRV LIGHT_HSL_CLI LIGHT_HSL_HUE_SRV LIGHT_HSL_SAT_SRV " \
	    "LIGHT_XYL_SRV LIGHT_XYL_SETUP_SRV LIGHT_XYL_CLI " \
	    "LIGHT_LC_SRV LIGHT_LC_SETUP_SRV LIGHT_LC_CLI"
	lighting_model_key_count = split(lighting_model_key_text,
	    lighting_model_keys, " ")
}

/<code class="code">0x[0-9A-F]+<\/code>/ {
	match($0, /0x[0-9A-F]+/)
	last_assigned_uuid = tolower(substr($0, RSTART, RLENGTH))
}
/>Primary Service</ { assigned_primary_service_uuid = last_assigned_uuid }
/>Secondary Service</ { assigned_secondary_service_uuid = last_assigned_uuid }
/>Include</ { assigned_include_uuid = last_assigned_uuid }
/>Characteristic</ { assigned_characteristic_uuid = last_assigned_uuid }
/>Characteristic Extended Properties</ {
	assigned_characteristic_extended_properties_uuid = last_assigned_uuid
}
/>Characteristic User Description</ {
	assigned_characteristic_user_description_uuid = last_assigned_uuid
}
/>Flags</ { assigned_flags_ad_type = last_assigned_uuid }

{
	for (profile_i = 1; profile_i <= profile_uuid_count; profile_i++) {
		profile_name = profile_uuid_name[profile_i]
		if (profile_uuid_value[profile_name] == "" &&
		    index($0, ">" profile_name "<") != 0) {
			profile_pending = profile_name
			profile_pending_lines = 8
			break
		}
	}
}
profile_pending_lines > 0 && /<code class="code">0x[0-9A-F]+<\/code>/ {
	match($0, /0x[0-9A-F]+/)
	profile_uuid_value[profile_pending] = tolower(substr($0, RSTART,
	    RLENGTH))
	profile_pending = ""
	profile_pending_lines = 0
}
profile_pending_lines > 0 { profile_pending_lines-- }

/0x0027/ {
	want_eatt = 16
	saw_value = 1
}
want_eatt > 0 {
	if ($0 ~ />EATT</)
		saw_eatt = 1
	if ($0 ~ />PSM or SPSM</)
		saw_kind = 1
	want_eatt--
}

/<p><code class="code">0x08<\/code><\/p>/ {
	match($0, /0x[0-9A-F]+/)
	ad_short_name = tolower(substr($0, RSTART, RLENGTH))
	want_short_name = 12
}
want_short_name > 0 {
	if ($0 ~ />Shortened Local Name</)
		saw_short_name = 1
	want_short_name--
}
/<p><code class="code">0x09<\/code><\/p>/ {
	match($0, /0x[0-9A-F]+/)
	ad_complete_name = tolower(substr($0, RSTART, RLENGTH))
	want_complete_name = 12
}
want_complete_name > 0 {
	if ($0 ~ />Complete Local Name</)
		saw_complete_name = 1
	want_complete_name--
}

/<p><code class="code">0x2902<\/code><\/p>/ {
	assigned_cccd_uuid = "0x2902"
	want_assigned_cccd = 8
}
want_assigned_cccd > 0 {
	if ($0 ~ />Client Characteristic Configuration</)
		saw_assigned_cccd = 1
	want_assigned_cccd--
}
/<p><code class="code">0x2908<\/code><\/p>/ {
	assigned_report_reference_uuid = "0x2908"
	want_assigned_report_reference = 8
}
want_assigned_report_reference > 0 {
	if ($0 ~ />Report Reference</)
		saw_assigned_report_reference = 1
	want_assigned_report_reference--
}

/>Boot Keyboard Input Report</ { want_boot_keyboard_uuid = 8 }
want_boot_keyboard_uuid > 0 && /0x2A22/ {
	match($0, /0x[0-9A-F]+/)
	boot_keyboard_uuid = tolower(substr($0, RSTART, RLENGTH))
	want_boot_keyboard_uuid = 0
}
want_boot_keyboard_uuid > 0 { want_boot_keyboard_uuid-- }
/>Boot Mouse Input Report</ { want_boot_mouse_uuid = 8 }
want_boot_mouse_uuid > 0 && /0x2A33/ {
	match($0, /0x[0-9A-F]+/)
	boot_mouse_uuid = tolower(substr($0, RSTART, RLENGTH))
	want_boot_mouse_uuid = 0
}
want_boot_mouse_uuid > 0 { want_boot_mouse_uuid-- }
/>Protocol Mode</ { want_protocol_mode_uuid = 8 }
want_protocol_mode_uuid > 0 && /0x2A4E/ {
	match($0, /0x[0-9A-F]+/)
	protocol_mode_uuid = tolower(substr($0, RSTART, RLENGTH))
	want_protocol_mode_uuid = 0
}
want_protocol_mode_uuid > 0 { want_protocol_mode_uuid-- }

# Mesh Model message opcodes.  The name-first table later in the official
# snapshot makes each value unambiguous even though an earlier table uses the
# opposite column order.
/>Light LC Mode Get</ { want_lc = "MODE_GET"; want_lc_lines = 8 }
/>Light LC Mode Set</ && $0 !~ /Unacknowledged/ {
	want_lc = "MODE_SET"; want_lc_lines = 8
}
/>Light LC Mode Set Unacknowledged/ {
	want_lc = "MODE_SET_UNACK"; want_lc_lines = 8
}
/>Light LC Mode Status/ { want_lc = "MODE_STATUS"; want_lc_lines = 8 }
/>Light LC OM Get</ { want_lc = "OM_GET"; want_lc_lines = 8 }
/>Light LC OM Set</ && $0 !~ /Unacknowledged/ {
	want_lc = "OM_SET"; want_lc_lines = 8
}
/>Light LC OM Set Unacknowledged/ {
	want_lc = "OM_SET_UNACK"; want_lc_lines = 8
}
/>Light LC OM Status/ { want_lc = "OM_STATUS"; want_lc_lines = 8 }
/>Light LC Light OnOff Get/ {
	want_lc = "LIGHT_ONOFF_GET"; want_lc_lines = 8
}
/>Light LC Light OnOff Set</ && $0 !~ /Unacknowledged/ {
	want_lc = "LIGHT_ONOFF_SET"; want_lc_lines = 8
}
/>Light LC Light OnOff Set Unacknowledged/ {
	want_lc = "LIGHT_ONOFF_SET_UNACK"; want_lc_lines = 8
}
/>Light LC Light OnOff Status/ {
	want_lc = "LIGHT_ONOFF_STATUS"; want_lc_lines = 8
}
/>Light LC Property Get/ { want_lc = "PROPERTY_GET"; want_lc_lines = 8 }
/>Light LC Property Set</ && $0 !~ /Unacknowledged/ {
	want_lc = "PROPERTY_SET"; want_lc_lines = 8
}
/>Light LC Property Set Unacknowledged/ {
	want_lc = "PROPERTY_SET_UNACK"; want_lc_lines = 8
}
/>Light LC Property Status/ {
	want_lc = "PROPERTY_STATUS"; want_lc_lines = 8
}
want_lc_lines > 0 && /<code class="code">0x[0-9A-F]+( 0x[0-9A-F]+)?<\/code>/ {
	match($0, /0x[0-9A-F]+( 0x[0-9A-F]+)?/)
	lc_value = tolower(substr($0, RSTART, RLENGTH))
	gsub(/ 0x/, "", lc_value)
	lc_opcode[want_lc] = lc_value
	want_lc = ""
	want_lc_lines = 0
}
want_lc_lines > 0 { want_lc_lines-- }

# HSL setup and xyL opcodes.  These immediately precede Light LC in the
# Assigned Numbers table, so extracting the full adjacent block also detects
# accidental collisions between model families.
/<p>Light HSL (Default|Range)/ || /<p>Light xyL / {
	want_lighting_name = $0
	sub(/^.*<p>/, "", want_lighting_name)
	sub(/<\/p>.*$/, "", want_lighting_name)
	want_lighting_lines = 8
}
want_lighting_lines > 0 && /<code class="code">0x[0-9A-F]+ 0x[0-9A-F]+<\/code>/ {
	match($0, /0x[0-9A-F]+ 0x[0-9A-F]+/)
	lighting_value = tolower(substr($0, RSTART, RLENGTH))
	gsub(/ 0x/, "", lighting_value)
	lighting_opcode[want_lighting_name] = lighting_value
	want_lighting_name = ""
	want_lighting_lines = 0
}
want_lighting_lines > 0 { want_lighting_lines-- }

# Complete contiguous two-octet Lighting Model opcode block.
/<p>Light (Lightness|CTL|HSL|xyL|LC) / {
	want_all_lighting_name = $0
	sub(/^.*<p>Light /, "", want_all_lighting_name)
	sub(/<\/p>.*$/, "", want_all_lighting_name)
	sub(/ Unacknowledged$/, "_UNACK", want_all_lighting_name)
	gsub(/ /, "_", want_all_lighting_name)
	want_all_lighting_name = toupper(want_all_lighting_name)
	want_all_lighting_lines = 8
}
want_all_lighting_lines > 0 && /<code class="code">0x[0-9A-F]+ 0x[0-9A-F]+<\/code>/ {
	match($0, /0x[0-9A-F]+ 0x[0-9A-F]+/)
	all_lighting_value = tolower(substr($0, RSTART, RLENGTH))
	gsub(/ 0x/, "", all_lighting_value)
	all_lighting_opcode[want_all_lighting_name] = all_lighting_value
	want_all_lighting_name = ""
	want_all_lighting_lines = 0
}
want_all_lighting_lines > 0 { want_all_lighting_lines-- }

# Complete contiguous Lighting Model identifier block.
/<p>Light (Lightness|CTL|HSL|xyL|LC) (Server|Setup Server|Client|Temperature Server|Hue Server|Saturation Server)<\/p>/ {
	want_lighting_model = $0
	sub(/^.*<p>/, "", want_lighting_model)
	sub(/<\/p>.*$/, "", want_lighting_model)
	sub(/ Setup Server$/, "_SETUP_SRV", want_lighting_model)
	sub(/ Temperature Server$/, "_TEMP_SRV", want_lighting_model)
	sub(/ Saturation Server$/, "_SAT_SRV", want_lighting_model)
	sub(/ Hue Server$/, "_HUE_SRV", want_lighting_model)
	sub(/ Server$/, "_SRV", want_lighting_model)
	sub(/ Client$/, "_CLI", want_lighting_model)
	gsub(/ /, "_", want_lighting_model)
	want_lighting_model = toupper(want_lighting_model)
	want_lighting_model_lines = 8
}
want_lighting_model_lines > 0 && /<code class="code">0x13[0-9A-F]+<\/code>/ {
	match($0, /0x13[0-9A-F]+/)
	lighting_model_value = tolower(substr($0, RSTART, RLENGTH))
	lighting_model_id[want_lighting_model] = lighting_model_value
	want_lighting_model = ""
	want_lighting_model_lines = 0
}
want_lighting_model_lines > 0 { want_lighting_model_lines-- }

END {
	if (!saw_value || !saw_eatt || !saw_kind) {
		print "incomplete Assigned Numbers EATT extraction" > "/dev/stderr"
		exit 1
	}
	if (!saw_short_name || !saw_complete_name ||
	    ad_short_name != "0x08" || ad_complete_name != "0x09") {
		print "incomplete Assigned Numbers Local Name extraction" > "/dev/stderr"
		exit 1
	}
	if (assigned_flags_ad_type != "0x01") {
		print "incomplete Assigned Numbers Flags AD type extraction" > "/dev/stderr"
		exit 1
	}
	if (boot_keyboard_uuid != "0x2a22" ||
	    boot_mouse_uuid != "0x2a33" || protocol_mode_uuid != "0x2a4e") {
		print "incomplete Assigned Numbers HIDS UUID extraction" > "/dev/stderr"
		exit 1
	}
	if (!saw_assigned_cccd || assigned_cccd_uuid != "0x2902") {
		print "incomplete Assigned Numbers CCCD UUID extraction" > "/dev/stderr"
		exit 1
	}
	if (!saw_assigned_report_reference ||
	    assigned_report_reference_uuid != "0x2908") {
		print "incomplete Assigned Numbers Report Reference UUID extraction" > "/dev/stderr"
		exit 1
	}
	if (assigned_primary_service_uuid != "0x2800" ||
	    assigned_secondary_service_uuid != "0x2801" ||
	    assigned_include_uuid != "0x2802" ||
	    assigned_characteristic_uuid != "0x2803" ||
	    assigned_characteristic_extended_properties_uuid != "0x2900" ||
	    assigned_characteristic_user_description_uuid != "0x2901") {
		print "incomplete Assigned Numbers declaration UUID extraction" > "/dev/stderr"
		exit 1
	}
	for (profile_i = 1; profile_i <= profile_uuid_count; profile_i++) {
		profile_name = profile_uuid_name[profile_i]
		if (profile_uuid_value[profile_name] != \
		    profile_uuid_expect[profile_name]) {
			print "incomplete Assigned Numbers profile UUID extraction: " \
			    profile_name " got " profile_uuid_value[profile_name] > "/dev/stderr"
			exit 1
		}
	}
	if (lc_opcode["MODE_GET"] != "0x8291" ||
	    lc_opcode["MODE_SET"] != "0x8292" ||
	    lc_opcode["MODE_SET_UNACK"] != "0x8293" ||
	    lc_opcode["MODE_STATUS"] != "0x8294" ||
	    lc_opcode["OM_GET"] != "0x8295" ||
	    lc_opcode["OM_SET"] != "0x8296" ||
	    lc_opcode["OM_SET_UNACK"] != "0x8297" ||
	    lc_opcode["OM_STATUS"] != "0x8298" ||
	    lc_opcode["LIGHT_ONOFF_GET"] != "0x8299" ||
	    lc_opcode["LIGHT_ONOFF_SET"] != "0x829a" ||
	    lc_opcode["LIGHT_ONOFF_SET_UNACK"] != "0x829b" ||
	    lc_opcode["LIGHT_ONOFF_STATUS"] != "0x829c" ||
	    lc_opcode["PROPERTY_GET"] != "0x829d" ||
	    lc_opcode["PROPERTY_SET"] != "0x62" ||
	    lc_opcode["PROPERTY_SET_UNACK"] != "0x63" ||
	    lc_opcode["PROPERTY_STATUS"] != "0x64") {
		print "incomplete Assigned Numbers Light LC opcode extraction" > "/dev/stderr"
		exit 1
	}
	if (lighting_opcode["Light HSL Default Get"] != "0x827b" ||
	    lighting_opcode["Light HSL Default Status"] != "0x827c" ||
	    lighting_opcode["Light HSL Range Get"] != "0x827d" ||
	    lighting_opcode["Light HSL Range Status"] != "0x827e" ||
	    lighting_opcode["Light HSL Default Set"] != "0x827f" ||
	    lighting_opcode["Light HSL Default Set Unacknowledged"] != "0x8280" ||
	    lighting_opcode["Light HSL Range Set"] != "0x8281" ||
	    lighting_opcode["Light HSL Range Set Unacknowledged"] != "0x8282" ||
	    lighting_opcode["Light xyL Get"] != "0x8283" ||
	    lighting_opcode["Light xyL Set"] != "0x8284" ||
	    lighting_opcode["Light xyL Set Unacknowledged"] != "0x8285" ||
	    lighting_opcode["Light xyL Status"] != "0x8286" ||
	    lighting_opcode["Light xyL Target Get"] != "0x8287" ||
	    lighting_opcode["Light xyL Target Status"] != "0x8288" ||
	    lighting_opcode["Light xyL Default Get"] != "0x8289" ||
	    lighting_opcode["Light xyL Default Status"] != "0x828a" ||
	    lighting_opcode["Light xyL Range Get"] != "0x828b" ||
	    lighting_opcode["Light xyL Range Status"] != "0x828c" ||
	    lighting_opcode["Light xyL Default Set"] != "0x828d" ||
	    lighting_opcode["Light xyL Default Set Unacknowledged"] != "0x828e" ||
	    lighting_opcode["Light xyL Range Set"] != "0x828f" ||
	    lighting_opcode["Light xyL Range Set Unacknowledged"] != "0x8290") {
		print "incomplete Assigned Numbers HSL/xyL opcode extraction" > "/dev/stderr"
		exit 1
	}
	for (i = 1; i <= lighting_key_count; i++) {
		expected_lighting_value = sprintf("0x82%02x", 74 + i)
		if (all_lighting_opcode[lighting_keys[i]] != expected_lighting_value) {
			print "incomplete Assigned Numbers full Lighting opcode extraction at " \
			    lighting_keys[i] > "/dev/stderr"
			exit 1
		}
	}
	for (i = 1; i <= lighting_model_key_count; i++) {
		expected_model_value = sprintf("0x%04x", 4863 + i)
		if (lighting_model_id[lighting_model_keys[i]] != expected_model_value) {
			print "incomplete Assigned Numbers Lighting model extraction at " \
			    lighting_model_keys[i] > "/dev/stderr"
			exit 1
		}
	}
	print "/* Generated from Bluetooth SIG Assigned Numbers HTML; do not edit. */"
	print "#ifndef TESTS_BLUETOOTH_SPEC_ASSIGNED_GENERATED_H"
	print "#define TESTS_BLUETOOTH_SPEC_ASSIGNED_GENERATED_H"
	print "/* Assigned Numbers, Protocol Identifiers: PSM/SPSM, EATT. */"
	print "#define BT_ASSIGNED_EATT_PSM_ORACLES(X) \\"
	print "\tX(NG_L2CAP_PSM_EATT, 0x0027)"
	print "/* Assigned Numbers, Generic Access Profile: Data Types. */"
	print "#define BT_ASSIGNED_AD_TYPE_FLAGS " assigned_flags_ad_type
	print "#define BT_ASSIGNED_AD_TYPE_SHORTENED_LOCAL_NAME " ad_short_name
	print "#define BT_ASSIGNED_AD_TYPE_COMPLETE_LOCAL_NAME " ad_complete_name
	print "/* Assigned Numbers, GATT Characteristics. */"
	print "#define BT_ASSIGNED_UUID_BOOT_KEYBOARD_INPUT_REPORT " boot_keyboard_uuid
	print "#define BT_ASSIGNED_UUID_BOOT_MOUSE_INPUT_REPORT " boot_mouse_uuid
	print "#define BT_ASSIGNED_UUID_PROTOCOL_MODE " protocol_mode_uuid
	print "#define BT_ASSIGNED_UUID_CCCD " assigned_cccd_uuid
	print "#define BT_ASSIGNED_UUID_REPORT_REFERENCE " \
	    assigned_report_reference_uuid
	print "#define BT_ASSIGNED_UUID_PRIMARY_SERVICE " assigned_primary_service_uuid
	print "#define BT_ASSIGNED_UUID_SECONDARY_SERVICE " assigned_secondary_service_uuid
	print "#define BT_ASSIGNED_UUID_INCLUDE " assigned_include_uuid
	print "#define BT_ASSIGNED_UUID_CHARACTERISTIC " assigned_characteristic_uuid
	print "#define BT_ASSIGNED_UUID_CHARACTERISTIC_EXTENDED_PROPERTIES " \
	    assigned_characteristic_extended_properties_uuid
	print "#define BT_ASSIGNED_UUID_CHARACTERISTIC_USER_DESCRIPTION " \
	    assigned_characteristic_user_description_uuid
	print "/* Assigned Numbers, GATT Services and Characteristics. */"
	for (profile_i = 1; profile_i <= profile_uuid_count; profile_i++) {
		profile_name = profile_uuid_name[profile_i]
		print "#define BT_ASSIGNED_UUID_" profile_uuid_symbol[profile_name] \
		    " " profile_uuid_value[profile_name]
	}
	print "/* Assigned Numbers, Mesh Model message opcodes. */"
	print "#define BT_ASSIGNED_MESH_LIGHT_LC_OPCODES(X) \\"
	print "\tX(MODE_GET, " lc_opcode["MODE_GET"] ") \\"
	print "\tX(MODE_SET, " lc_opcode["MODE_SET"] ") \\"
	print "\tX(MODE_SET_UNACK, " lc_opcode["MODE_SET_UNACK"] ") \\"
	print "\tX(MODE_STATUS, " lc_opcode["MODE_STATUS"] ") \\"
	print "\tX(OM_GET, " lc_opcode["OM_GET"] ") \\"
	print "\tX(OM_SET, " lc_opcode["OM_SET"] ") \\"
	print "\tX(OM_SET_UNACK, " lc_opcode["OM_SET_UNACK"] ") \\"
	print "\tX(OM_STATUS, " lc_opcode["OM_STATUS"] ") \\"
	print "\tX(LIGHT_ONOFF_GET, " lc_opcode["LIGHT_ONOFF_GET"] ") \\"
	print "\tX(LIGHT_ONOFF_SET, " lc_opcode["LIGHT_ONOFF_SET"] ") \\"
	print "\tX(LIGHT_ONOFF_SET_UNACK, " lc_opcode["LIGHT_ONOFF_SET_UNACK"] ") \\"
	print "\tX(LIGHT_ONOFF_STATUS, " lc_opcode["LIGHT_ONOFF_STATUS"] ") \\"
	print "\tX(PROPERTY_GET, " lc_opcode["PROPERTY_GET"] ") \\"
	print "\tX(PROPERTY_SET, " lc_opcode["PROPERTY_SET"] ") \\"
	print "\tX(PROPERTY_SET_UNACK, " lc_opcode["PROPERTY_SET_UNACK"] ") \\"
	print "\tX(PROPERTY_STATUS, " lc_opcode["PROPERTY_STATUS"] ")"
	print "#define BT_ASSIGNED_MESH_LIGHT_HSL_SETUP_OPCODES(X) \\"
	print "\tX(DEFAULT_GET, " lighting_opcode["Light HSL Default Get"] ") \\"
	print "\tX(DEFAULT_STATUS, " lighting_opcode["Light HSL Default Status"] ") \\"
	print "\tX(RANGE_GET, " lighting_opcode["Light HSL Range Get"] ") \\"
	print "\tX(RANGE_STATUS, " lighting_opcode["Light HSL Range Status"] ") \\"
	print "\tX(DEFAULT_SET, " lighting_opcode["Light HSL Default Set"] ") \\"
	print "\tX(DEFAULT_SET_UNACK, " lighting_opcode["Light HSL Default Set Unacknowledged"] ") \\"
	print "\tX(RANGE_SET, " lighting_opcode["Light HSL Range Set"] ") \\"
	print "\tX(RANGE_SET_UNACK, " lighting_opcode["Light HSL Range Set Unacknowledged"] ")"
	print "#define BT_ASSIGNED_MESH_LIGHT_XYL_OPCODES(X) \\"
	print "\tX(GET, " lighting_opcode["Light xyL Get"] ") \\"
	print "\tX(SET, " lighting_opcode["Light xyL Set"] ") \\"
	print "\tX(SET_UNACK, " lighting_opcode["Light xyL Set Unacknowledged"] ") \\"
	print "\tX(STATUS, " lighting_opcode["Light xyL Status"] ") \\"
	print "\tX(TARGET_GET, " lighting_opcode["Light xyL Target Get"] ") \\"
	print "\tX(TARGET_STATUS, " lighting_opcode["Light xyL Target Status"] ") \\"
	print "\tX(DEFAULT_GET, " lighting_opcode["Light xyL Default Get"] ") \\"
	print "\tX(DEFAULT_STATUS, " lighting_opcode["Light xyL Default Status"] ") \\"
	print "\tX(RANGE_GET, " lighting_opcode["Light xyL Range Get"] ") \\"
	print "\tX(RANGE_STATUS, " lighting_opcode["Light xyL Range Status"] ") \\"
	print "\tX(DEFAULT_SET, " lighting_opcode["Light xyL Default Set"] ") \\"
	print "\tX(DEFAULT_SET_UNACK, " lighting_opcode["Light xyL Default Set Unacknowledged"] ") \\"
	print "\tX(RANGE_SET, " lighting_opcode["Light xyL Range Set"] ") \\"
	print "\tX(RANGE_SET_UNACK, " lighting_opcode["Light xyL Range Set Unacknowledged"] ")"
	print "#define BT_ASSIGNED_MESH_LIGHTING_SIG2_OPCODES(X) \\"
	for (i = 1; i <= lighting_key_count; i++)
		print "\tX(" lighting_keys[i] ", " \
		    all_lighting_opcode[lighting_keys[i]] ")" \
		    (i < lighting_key_count ? " \\" : "")
	print "#define BT_ASSIGNED_MESH_LIGHTING_MODEL_IDS(X) \\"
	for (i = 1; i <= lighting_model_key_count; i++)
		print "\tX(" lighting_model_keys[i] ", " \
		    lighting_model_id[lighting_model_keys[i]] ")" \
		    (i < lighting_model_key_count ? " \\" : "")
	print "#endif"
}
