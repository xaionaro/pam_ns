/*
   pam_ns — PAM module to call unshare()/setns()
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
#include <proc/readproc.h>
#include <pwd.h>


#define PATH_SO_pam_ns "/lib/security/pam_ns.so"

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
	key_t semkey = ftok ( PATH_SO_pam_ns, 'P' );
	*semid_p = semget ( semkey, 1, IPC_CREAT );

	if ( *semid_p == -1 )
		return 1;

	if ( semop ( *semid_p, sb_p, 1 ) == -1 )
		return 2;

	return 0;
}

static inline int ns_unlock (
    struct sembuf *sb_p,
    int *semid_p
)
{
	sb_p->sem_op = 1;

	if ( semop ( *semid_p, sb_p, 1 ) == -1 )
		return 2;

	return 0;
}

static inline int ns2procns_map (
    int clone_flag
)
{
	switch ( clone_flag ) {
		case CLONE_NEWIPC:
			return IPCNS;

		case CLONE_NEWNET:
			return NETNS;

		case CLONE_NEWNS:
			return MNTNS;

		case CLONE_NEWPID:
			return PIDNS;

		case CLONE_NEWUSER:
			return USERNS;

		case CLONE_NEWUTS:
			return UTSNS;
	}

	// TODO: This line shouldn't never happened, so it's required to add some debugging in this place
	return 0;
}

static inline int ns_attach (
    pam_handle_t *pam,
    int flags,
    proc_t *proc_info_p,
    int argc,
    const char *argv[]
)
{
	x_pam_syslog ( pam, LOG_INFO, "attaching to namespaces of process TID == %u", proc_info_p->tid );

	while ( --argc ) {
		const char *arg = argv[argc];
#define CMP_AND_SETNS(pam, arg, v) \
	if ( ! strcmp ( arg, #v ) ) {\
		x_pam_syslog ( pam, LOG_INFO, "unsharing " #v ); \
		if (setns(proc_info_p->ns[ns2procns_map(v)], v)) {\
			x_pam_syslog ( pam, LOG_ERR, "got error while setns(%lu, "#v"): %s", proc_info_p->ns[ns2procns_map(v)], strerror(errno) );\
			return PAM_SESSION_ERR;\
		}\
		continue;\
	}
		CMP_AND_SETNS ( pam, arg, CLONE_NEWIPC );
		CMP_AND_SETNS ( pam, arg, CLONE_NEWNET );
		CMP_AND_SETNS ( pam, arg, CLONE_NEWNS );
		CMP_AND_SETNS ( pam, arg, CLONE_NEWPID );
		CMP_AND_SETNS ( pam, arg, CLONE_NEWUSER );
		CMP_AND_SETNS ( pam, arg, CLONE_NEWUTS );
#undef CMP_AND_UNSHARE
		x_pam_syslog ( pam, LOG_ERR, "invalid argument: %s (see \"man 2 pam_ns\")", arg );
		return PAM_SESSION_ERR;
	}

	return PAM_SUCCESS;;
}

static inline int ns_detach (
    pam_handle_t *pam,
    int flags,
    int argc,
    const char *argv[]
)
{
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
		x_pam_syslog ( pam, LOG_ERR, "invalid argument: %s (see \"man 2 pam_ns\")", arg );
		return PAM_SESSION_ERR;
	}

	return PAM_SUCCESS;
}

static inline int pam_get_uidgid (
    pam_handle_t *pam,
    int flags,
    uid_t *user_uid_p,
    gid_t *user_gid_p
)
{
	const char *user_login;
	int rc = pam_get_item ( pam, PAM_USER, ( const void ** ) &user_login );

	if ( rc != PAM_SUCCESS ) {
		x_pam_syslog ( pam, LOG_ERR, "internal error: cannot get user login from PAM; rc == %i", rc );
		return PAM_SESSION_ERR;
	}

	struct passwd *user = getpwnam ( user_login );

	if ( user == NULL ) {
		x_pam_syslog ( pam, LOG_ERR, "error: cannot find user with login \"%s\"", user_login );
		return PAM_SESSION_ERR;
	}

	x_pam_syslog ( pam, LOG_INFO, "user info: uid == %u; gid == %u", user->pw_uid, user->pw_gid );

	if ( user_uid_p != NULL )
		*user_uid_p = user->pw_uid;

	if ( user_gid_p != NULL )
		*user_uid_p = user->pw_gid;

	return PAM_SUCCESS;
}

static inline int ns_find_attach (
    pam_handle_t *pam,
    int flags,
    groupby_t groupby,
    int argc,
    const char *argv[]
)
{
	PROCTAB *proc = openproc ( PROC_FILLNS );
	proc_t proc_info;
	memset ( &proc_info, 0, sizeof ( proc_info ) );
	uid_t user_uid = -1;
	gid_t user_gid = -1;

	if ( pam_get_uidgid ( pam, flags, &user_uid, &user_gid ) != PAM_SUCCESS )
		return PAM_SESSION_ERR;

	while ( readproc ( proc, &proc_info ) != NULL ) {
		switch ( groupby ) {
			case GB_USER:
				if ( proc_info.ruid == user_uid ) {
					return ns_attach ( pam, flags, &proc_info, argc, argv );
				}

				break;

			case GB_GROUP:
				if ( proc_info.rgid == user_gid ) {
					return ns_attach ( pam, flags, &proc_info, argc, argv );
				}

				break;

			default:
				{} // anti-warning
		}
	}

	return PAM_SESSION_ERR;
}

static inline int ns_setup (
    pam_handle_t *pam,
    int flags,
    groupby_t groupby,
    int argc,
    const char *argv[]
)
{
	switch ( groupby ) {
		case GB_SESSION:
			return ns_detach ( pam, flags, argc, argv );

		case GB_USER:
		case GB_GROUP: {
				struct sembuf sb;
				int semid;
				int rc_ns;
				int rc;

				if ( ( rc = ns_lock ( &sb, &semid ) ) ) {
					x_pam_syslog ( pam, LOG_ERR, "internal error: cannot setup semaphores (rc == %u)", rc );
					return PAM_SESSION_ERR;
				}

				rc_ns = ns_find_attach ( pam, flags, groupby, argc, argv );

				if ( rc_ns == PAM_SESSION_ERR )				// if didn't found where to attach to
					rc_ns = ns_detach ( pam, flags, argc, argv );	// then just detach from current namespaces

				if ( ( rc = ns_unlock ( &sb, &semid ) ) ) {
					x_pam_syslog ( pam, LOG_ERR, "internal error: cannot free semaphores (rc == %u)", rc );
					return PAM_SESSION_ERR;
				}

				return rc_ns;
			}

		default:
			{} // anti-warning
	}

	x_pam_syslog ( pam, LOG_ERR, "internal error: unknown \"groupby\" value: %u", groupby );
	return PAM_SESSION_ERR;
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
		x_pam_syslog ( pam, LOG_ERR, "not enough arguments (see \"man 2 pam_ns\")" );
		return PAM_SESSION_ERR;
	}

	{
		const char *arg = argv[0];
		groupby_t groupby = GB_UNKNOWN;

		if ( !strcmp ( arg, "session" ) ) {
			groupby = GB_SESSION;
		} else if ( !strcmp ( arg, "user" ) ) {
			groupby = GB_USER;
		} else if ( !strcmp ( arg, "group" ) ) {
			groupby = GB_GROUP;
		} else {
			x_pam_syslog ( pam, LOG_ERR, "invalid argument: %s (see \"man 2 pam_ns\"; should be \"session\", \"user\" or \"group\")", arg );
			return PAM_SESSION_ERR;
		}

		rc = ns_setup ( pam, flags, groupby, argc, argv );
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
