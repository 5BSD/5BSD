#
# .login - csh login script, read by login shell, after `.cshrc' at login.
#
# See also csh(1), environ(7).
#

# Query terminal size; useful for serial lines.
if ( -x /usr/bin/resizewin ) /usr/bin/resizewin -z

# Show a 5BSD tip of the day at login.
if ( -x /usr/bin/fortune ) /usr/bin/fortune 5bsd-tips
