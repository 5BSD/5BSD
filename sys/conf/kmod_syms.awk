
# Read a previously checked nm listing. The caller runs nm and checks its
# status before invoking this transform; awk close() need not report pipe status.
BEGIN {
	if (modname == "")
		modname = ARGV[1]
        symbol_file = ARGV[1]
        while ((status = (getline < symbol_file)) > 0) {
                if (match($0, /^[^[:space:]]+ [^AU] (.*)$/)) {
                        syms[$3] = $2
                }
        }
        command_status = close(symbol_file)
        if (status < 0 || command_status != 0) {
                print "Cannot read module symbol listing: " ARGV[1] > "/dev/stderr"
                failed = 1
                exit 1
        }
        delete ARGV[1]
}

# De-list symbols from the export list.
{
	smbl = $0
	if (!(smbl in syms)) {
		printf "Symbol %s is not present in %s\n",	\
		    smbl, modname > "/dev/stderr"
	}
	delete syms[smbl]
}

# Strip commons, make everything else local.
END {
        if (failed)
                exit 1
        for (member in syms) {
                if (syms[member] == "C")
                        print "-N" member
                else
                        print "-L" member
        }
}
