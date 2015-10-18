#
# Regular cron jobs for the libpam-ns package
#
0 4	* * *	root	[ -x /usr/bin/libpam-ns_maintenance ] && /usr/bin/libpam-ns_maintenance
