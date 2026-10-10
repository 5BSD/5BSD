# Login environment for zsh.  PATH is provided by login.conf.
export EDITOR=vi
export PAGER=less

if [[ -o interactive && -t 0 && -x /usr/bin/resizewin ]]; then
	/usr/bin/resizewin -z
fi
