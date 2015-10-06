/*
   pam_unshare — PAM module to call unshare()
    Copyright (C) 2015  Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <sched.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>


#define TOSTR(a) # a
#define XTOSTR(a) TOSTR(a)

#define x_pam_syslog(...) if ((flags & PAM_SILENT) == 0) pam_syslog(__VA_ARGS__)


PAM_EXTERN int pam_sm_open_session (
    pam_handle_t *pam,
    int flags,
    int argc,
    const char *argv[]
)
{
	x_pam_syslog ( pam, LOG_INFO, "pam_unshare.so: open session" );

	if ( argc < 1 ) {
		x_pam_syslog ( pam, LOG_ERR, "pam_unshare.so: not enough arguments (see man 2 pam_unshare)" );
		return PAM_SESSION_ERR;
	}

	while ( argc-- ) {
		const char *arg = argv[argc];

#define CMP_AND_UNSHARE(pam, arg, v) \
		if ( ! strcmp ( arg, XTOSTR(v) ) ) {\
			x_pam_syslog ( pam, LOG_INFO, "pam_unshare.so: unsharing " XTOSTR(v) ); \
			if (unshare(v)) {\
				x_pam_syslog ( pam, LOG_ERR, "pam_unshare.so: got error while unshare("XTOSTR(v)"): %s", strerror(errno) );\
				return PAM_SESSION_ERR;\
			}\
			continue;\
		}

		CMP_AND_UNSHARE ( pam, arg, CLONE_FILES );
		CMP_AND_UNSHARE ( pam, arg, CLONE_FS );
		CMP_AND_UNSHARE ( pam, arg, CLONE_NEWIPC );
		CMP_AND_UNSHARE ( pam, arg, CLONE_NEWNET );
		CMP_AND_UNSHARE ( pam, arg, CLONE_NEWNS );
		CMP_AND_UNSHARE ( pam, arg, CLONE_NEWPID );
		CMP_AND_UNSHARE ( pam, arg, CLONE_NEWUSER );
		CMP_AND_UNSHARE ( pam, arg, CLONE_NEWUTS );
		CMP_AND_UNSHARE ( pam, arg, CLONE_SYSVSEM );
#undef CMP_AND_UNSHARE
	}

	return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_close_session (
    pam_handle_t *pam,
    int flags,
    int argc,
    const char *argv[]
)
{
	x_pam_syslog ( pam, LOG_INFO, "pam_unshare.so: close session" );
	return PAM_SUCCESS;
}
