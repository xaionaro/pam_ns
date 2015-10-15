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
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>


#define PATH_SO_PAM_UNSHARE "/lib/security/pam_unshare.so"

#define x_pam_syslog(...) if ((flags & PAM_SILENT) == 0) pam_syslog(__VA_ARGS__)

enum groupby {
	GB_UNKNOWN = 0,
	GB_SESSION,
	GB_USER,
	GB_GROUP,
}; 
typedef enum groupby groupby_t;

static inline int ns_lock (
    struct sembuf *sb_p,
    int *semid_p
)
{
	sb_p->sem_num = 0;
	sb_p->sem_op = -1;
	sb_p->sem_flg = SEM_UNDO;

	key_t semkey = ftok(PATH_SO_PAM_UNSHARE, 'P');

	*semid_p = semget(semkey, 1, IPC_CREAT);
	if ( *semid_p == -1 )
		return 1;

	if ( semop(*semid_p, sb_p, 1) == -1 )
		return 2;

	return 0;
}

static inline int ns_unlock (
    struct sembuf *sb_p,
    int *semid_p
)
{
	sb_p->sem_op = 1;

	if (semop(*semid_p, sb_p, 1) == -1)
		return 2;

	return 0;
}

static inline void ns_attach_or_detach (	// Attach to appropriate namespaces if exists; otherwise just detach from the current namespace
    groupby_t groupby
)
{
	return;
}

static inline int ns_setup (
    pam_handle_t *pam,
    int flags,
    groupby_t groupby
)
{
	switch (groupby) {
		case GB_SESSION:
			break;
		case GB_USER:
		case GB_GROUP: {
			struct sembuf sb;
			int semid;

			int rc;
			if ( ( rc = ns_lock(&sb, &semid) ) ) {
				x_pam_syslog ( pam, LOG_ERR, "internal error: cannot setup semaphores (rc == %u)", rc );
				return PAM_SESSION_ERR;
			}

			ns_attach_or_detach (groupby);

			if ( ( rc = ns_unlock(&sb, &semid) ) ) {
				x_pam_syslog ( pam, LOG_ERR, "internal error: cannot free semaphores (rc == %u)", rc );
				return PAM_SESSION_ERR;
			}
			break;
		}
		default:
			x_pam_syslog ( pam, LOG_ERR, "internal error: unknown \"groupby\" value: %u", groupby );
			return PAM_SESSION_ERR;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session (
    pam_handle_t *pam,
    int flags,
    int argc,
    const char *argv[]
)
{
	int rc = PAM_SESSION_ERR;

	x_pam_syslog ( pam, LOG_INFO, "opening session" );

	if ( argc < 2 ) {
		x_pam_syslog ( pam, LOG_ERR, "not enough arguments (see \"man 2 pam_unshare\")" );
		return PAM_SESSION_ERR;
	}

	while ( --argc ) {
		const char *arg = argv[argc];
#define CMP_AND_UNSHARE(pam, arg, v) \
		if ( ! strcmp ( arg, #v ) ) {\
			x_pam_syslog ( pam, LOG_INFO, "unsharing " #v ); \
			if (unshare(v)) {\
				x_pam_syslog ( pam, LOG_ERR, "got error while unshare("#v"): %s", strerror(errno) );\
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
		x_pam_syslog ( pam, LOG_ERR, "invalid argument: %s (see \"man 2 pam_unshare\")", arg );
		return PAM_SESSION_ERR;
	}

	{
		const char *arg = argv[0];

		groupby_t groupby = GB_UNKNOWN;
		if ( !strcmp ( arg, "session" ) ) {
			groupby = GB_SESSION;
		} else
		if ( !strcmp ( arg, "user" ) ) {
			groupby = GB_USER;
		} else
		if ( !strcmp ( arg, "group" ) ) {
			groupby = GB_GROUP;
		} else
		{
			x_pam_syslog ( pam, LOG_ERR, "invalid argument: %s (see \"man 2 pam_unshare\"; should be \"session\", \"user\" or \"group\")", arg );
			return PAM_SESSION_ERR;
		}

		rc = ns_setup (pam, flags, groupby);
	}

	return rc;
}


PAM_EXTERN int pam_sm_close_session (
    pam_handle_t *pam,
    int flags,
    int argc,
    const char *argv[]
)
{
	x_pam_syslog ( pam, LOG_INFO, "closing session" );
	return PAM_SUCCESS;
}
