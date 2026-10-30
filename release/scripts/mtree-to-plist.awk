#!/usr/bin/awk
/^[^#]/ {
	gsub(/^\./,"", $1)
	uname = gname = mode = flags = tags = type = ""
	for (i=2; i<=NF; i++) {
		if ($i ~ /^uname=/) {
			uname=$i
			gsub(/uname=/, "", uname)
		} else if ($i ~ /^gname=/) {
			gname=$i
			gsub(/gname=/, "", gname)
		} else if ($i ~ /^mode=/) {
			mode=$i
			gsub(/mode=/,"", mode)
		} else if ($i ~ /^flags=/) {
			flags=$i
			gsub(/flags=/, "", flags)
		} else if ($i ~ /^tags=/) {
			tags=$i
			gsub(/tags=/, "", tags)
		} else if ($i ~ /^type=dir/) {
			type="dir"
		}
	}
	# mtree spells an empty flag set as none; pkg expects an empty field.
	if (flags == "none")
		flags = ""
	# Preserve the declared metadata of untagged scaffolding. In world mode,
	# each package also declares the ancestors needed by its own payloads.
	# Never infer permissions from the builder filesystem or host umask.
	if (complete_dirs != "" && type == "dir" && $1 != "") {
		attributes = "@dir(" uname "," gname "," mode "," flags ") "
		if ($1 in directory && directory[$1] != attributes) {
			print "conflicting METALOG directory metadata: " $1 > "/dev/stderr"
			failed = 1
		}
		directory[$1] = attributes
		if (uname == "" || gname == "" || mode == "")
			incomplete[$1] = 1
	}
	if (kernel != "") {
		if ($1 ~ /^\/boot\/dtb\//) {
			tags="package=dtb"
		} else if (tags !~ /(^|,)package=/) {
			tags="package=kernel"
		}
	}
	if (length(tags) == 0)
		next
	if (tags ~ /package=/) {
		ext = pkgname = pkgend = ""
		split(tags, a, ",");
		for (i in a) {
			if (a[i] ~ /^package=/) {
				pkgname=a[i]
				gsub(/package=/, "", pkgname)
			} else if (a[i] == "config") {
				type="config"
			} else if (a[i] == "development" || a[i] == "debug" || a[i] == "docs") {
				pkgend=a[i]
			} else {
				if (ext != "")
					ext=ext"-"a[i]
				else
					ext=a[i]
			}
		}
		basepkg = pkgname
		if (ext != "") {
			pkgname=pkgname"-"ext
		}
		if (pkgend != "") {
			if (pkgend == "docs") {
				pkgname=pkgend
			} else {
				pkgname=pkgname"-"pkgend
			}
		}
	} else {
		print "No packages specified in line: $0"
		next
	}
	if (kernel != "" && basepkg == "kernel") {
		output="kernel"
		if (_kernconf != "") {
			output = output "." _kernconf
		}
		if ($1 ~ /^\/usr\/lib\/debug\/boot/) {
			output=output"-dbg.plist"
		} else {
			output=output".plist"
		}
	} else {
		output=pkgname".plist"
	}

	print "@"type"("uname","gname","mode","flags") " $1 > output
	if (complete_dirs != "") {
		payload[++payload_count] = output SUBSEP $1
		if (type == "dir")
			declared[output SUBSEP $1] = 1
	}
}

END {
	if (complete_dirs != "") {
		for (entry = 1; entry <= payload_count; entry++) {
			split(payload[entry], parts, SUBSEP)
			output = parts[1]
			parent = parts[2]
			while (sub(/\/[^\/]*$/, "", parent) && parent != "") {
				key = output SUBSEP parent
				if (key in declared)
					continue
				if (!(parent in directory) || parent in incomplete) {
					print "missing complete METALOG parent directory: " parent > "/dev/stderr"
					failed = 1
					continue
				}
				print directory[parent] parent > output
				declared[key] = 1
			}
		}
	}
	exit failed
}
