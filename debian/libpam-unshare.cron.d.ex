#
# Regular cron jobs for the libpam-unshare package
#
0 4	* * *	root	[ -x /usr/bin/libpam-unshare_maintenance ] && /usr/bin/libpam-unshare_maintenance
