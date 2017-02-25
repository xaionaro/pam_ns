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
#include <stdlib.h>
#include <syslog.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <proc/readproc.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>


#define PATH_SO_pam_ns "/lib/security/pam_ns.so"

#define PATH_SETGROUPS "/proc/self/setgroups"

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
/*
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
*/

static inline const char *ns_name (
    int clone_flag
)
{
	switch ( clone_flag ) {
		case CLONE_NEWIPC:
			return "ipc";

		case CLONE_NEWNET:
			return "net";

		case CLONE_NEWNS:
			return "mnt";

		case CLONE_NEWPID:
			return "pid";

		case CLONE_NEWUSER:
			return "user";

		case CLONE_NEWUTS:
			return "uts";
	}

	// TODO: This line shouldn't never happened, so it's required to add some debugging in this place
	return "doesnt///exists///";
}

static inline int setgroups_deny (
    pam_handle_t *pam,
    int flags
)
{
	int fd;
	fd = open ( PATH_SETGROUPS, O_CLOEXEC | O_WRONLY );

	if ( fd == -1 ) {
		if ( errno == ENOENT ) {
			return 0;
		}

		x_pam_syslog ( pam, LOG_ERR, "Cannot open() file \""PATH_SETGROUPS"\": %s", strerror ( errno ) );
		return -1;
	}

	if ( write ( fd, "deny", 4 ) != 4 ) {
		x_pam_syslog ( pam, LOG_ERR, "Something gone wrong while writting to \""PATH_SETGROUPS"\" (current errno: %i: %s) (current uid/gid/euid/egid: %i/%i/%i/%i)", errno, strerror ( errno ), getuid(), getgid(), geteuid(), getegid() );
		return -1;
	}

	if ( close ( fd ) == -1 ) {
		x_pam_syslog ( pam, LOG_ERR, "Cannot close() file \""PATH_SETGROUPS"\": %s", strerror ( errno ) );
		return -1;
	}

	x_pam_syslog ( pam, LOG_INFO, "sent \"deny\" to \"" PATH_SETGROUPS "\"" );
	return 0;
}

static inline int set_xidmap (
    pam_handle_t *pam,
    int flags,
    const char *arg,
    const char *map_path
)
{
	if ( map_path == NULL || arg == NULL ) {
		x_pam_syslog ( pam, LOG_ERR, "Internal error: map_path == NULL || arg == NULL" );
		return -1;
	}

	int mapfd = open ( map_path, O_CLOEXEC | O_WRONLY );

	if ( mapfd == -1 ) {
		x_pam_syslog ( pam, LOG_ERR, "Cannot open() file \"%s\": %s", map_path, strerror ( errno ) );
		return -1;
	}

	char *buf = strdup ( arg );

	if ( buf == NULL ) {
		x_pam_syslog ( pam, LOG_ERR, "Cannot allocate memory for a buffer: %s", strerror ( errno ) );
		return -1;
	}

	char *ptr = buf;

	while ( *ptr != 0 ) {
		switch ( *ptr ) {
			case ':':
				*ptr = ' ';
				break;

			case ',':
				*ptr = '\n';
				break;
		}

		ptr++;
	}

	ssize_t l = strlen ( buf );
	ssize_t w = write ( mapfd, buf, l );

	if ( w != l ) {
		x_pam_syslog ( pam, LOG_ERR, "Something gone wrong while writting to \"%s\": %li != %li (current errno: %i: %s) (current uid/gid/euid/egid: %i/%i/%i/%i), value: \"%s\"", map_path, w, l, errno, strerror ( errno ), getuid(), getgid(), geteuid(), getegid(), buf );
		return -1;
	}

	x_pam_syslog ( pam, LOG_INFO, "sent \"%s\" to \"%s\"", buf, map_path );

	if ( close ( mapfd ) == -1 ) {
		x_pam_syslog ( pam, LOG_ERR, "Cannot close() file \"%s\": %s", map_path, strerror ( errno ) );
		return -1;
	}

	return 0;
}

static inline int set_uidmap (
    pam_handle_t *pam,
    int flags,
    const char *arg
)
{
	return set_xidmap ( pam, flags, arg, "/proc/self/uid_map" );
}

static inline int set_gidmap (
    pam_handle_t *pam,
    int flags,
    const char *arg
)
{
	return set_xidmap ( pam, flags, arg, "/proc/self/gid_map" );
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
#define CMP_AND_SETNS(pam, arg, v, onsuccess) \
	if ( ! strcmp ( arg, #v ) ) {\
		char path[PATH_MAX+1];\
		snprintf(path, PATH_MAX, "/proc/%u/ns/%s", proc_info_p->tid, ns_name(v));\
		x_pam_syslog ( pam, LOG_INFO, "attaching " #v " by path \"%s\"", path ); \
		int fd = open(path, O_RDONLY);\
		if (fd == -1) {\
			x_pam_syslog ( pam, LOG_ERR, "got error while open(\"%s\", O_RDONLY): %s", path, strerror(errno) );\
			return PAM_SESSION_ERR;\
		}\
		if (setns(fd, v)) {\
			x_pam_syslog ( pam, LOG_ERR, "got error while setns(%i [path \"%s\"], "#v"): %s", fd, path, strerror(errno) );\
			return PAM_SESSION_ERR;\
		}\
		close(fd);\
		onsuccess;\
	}
		CMP_AND_SETNS ( pam, arg, CLONE_NEWIPC, continue );
		CMP_AND_SETNS ( pam, arg, CLONE_NEWNET, continue );
		CMP_AND_SETNS ( pam, arg, CLONE_NEWNS, continue );
		CMP_AND_SETNS ( pam, arg, CLONE_NEWPID, continue );
		CMP_AND_SETNS ( pam, arg, CLONE_NEWUTS, continue );
		CMP_AND_SETNS ( pam, arg, CLONE_NEWUSER, continue );
#undef CMP_AND_UNSHARE
		x_pam_syslog ( pam, LOG_ERR, "setns: invalid argument: \"%s\" (see \"man 2 pam_ns\")", arg );
		return PAM_SESSION_ERR;
	}

	return PAM_SUCCESS;
}



static inline int ns_detach (
    pam_handle_t *pam,
    int flags,
    int argc,
    const char *argv[]
)
{
	int argi = 1;

	while ( argi < argc ) {
		const char *arg = argv[argi++];
#define CMP_AND_UNSHARE(pam, arg, v, onsuccess) \
	if ( ! strcmp ( arg, #v ) ) {\
		x_pam_syslog ( pam, LOG_INFO, "unsharing " #v ); \
		if (unshare(v)) {\
			x_pam_syslog ( pam, LOG_ERR, "got error while unshare("#v"): %s", strerror(errno) );\
			return PAM_SESSION_ERR;\
		}\
		onsuccess;\
	}
		CMP_AND_UNSHARE ( pam, arg, CLONE_FILES, continue );
		CMP_AND_UNSHARE ( pam, arg, CLONE_FS, continue );
		CMP_AND_UNSHARE ( pam, arg, CLONE_NEWIPC, continue );
		CMP_AND_UNSHARE ( pam, arg, CLONE_NEWNET, continue );
		CMP_AND_UNSHARE ( pam, arg, CLONE_NEWNS, continue );
		CMP_AND_UNSHARE ( pam, arg, CLONE_NEWPID, continue );
		CMP_AND_UNSHARE ( pam, arg, CLONE_NEWUTS, continue );
		CMP_AND_UNSHARE ( pam, arg, CLONE_SYSVSEM, continue );

		if ( ! strcmp ( arg, "CLONE_NEWUSER" ) ) {
			if ( argc - argi < 2 ) {
				x_pam_syslog ( pam, LOG_ERR, "expected additional arguments to for \"CLONE_NEWUSER\" (see \"man 2 pam_ns\")" );
				return PAM_SESSION_ERR;
			}

			//x_pam_syslog ( pam, LOG_INFO, "preparing for CLONE_NEWUSER: fork (current uid/gid/euid/egid: %i/%i/%i/%i)", getuid(), getgid(), geteuid(), getegid()  );
			/*pid_t child_pid = fork();
			if (child_pid == -1) {
				x_pam_syslog ( pam, LOG_ERR, "got error while fork(): %s", strerror(errno) );
				return PAM_SESSION_ERR;
			}

			if (child_pid == 0) */
			x_pam_syslog ( pam, LOG_INFO, "unsharing CLONE_NEWUSER" );

			if ( unshare ( CLONE_NEWUSER ) ) {
				x_pam_syslog ( pam, LOG_ERR, "got error while unshare(CLONE_NEWUSER): %s", strerror ( errno ) );
				return PAM_SESSION_ERR;
			}

			if ( setgroups_deny ( pam, flags ) )
			{
				x_pam_syslog ( pam, LOG_ERR, "Got error while sending data to "PATH_SETGROUPS );
				return PAM_SESSION_ERR;
			}


			if ( set_uidmap ( pam, flags, argv[argi++] ) ) {
				x_pam_syslog ( pam, LOG_ERR, "Got error while sending data to /proc/self/uid_map" );
				return PAM_SESSION_ERR;
			}

			if ( set_gidmap ( pam, flags, argv[argi++] ) ) {
				x_pam_syslog ( pam, LOG_ERR, "Got error while sending data to /proc/self/gid_map" );
				return PAM_SESSION_ERR;
			}

			/*if ( set_uidmap ( pam, flags, "0 0 1,1000 1000 1" ) ) {
				x_pam_syslog ( pam, LOG_ERR, "Got error while sending data to /proc/self/uid_map" );
				return PAM_SESSION_ERR;
			}

			if ( set_gidmap ( pam, flags, "0 0 1,1000 1000 1" ) ) {
				x_pam_syslog ( pam, LOG_ERR, "Got error while sending data to /proc/self/gid_map" );
				return PAM_SESSION_ERR;
			}*/

			continue;
		}

#undef CMP_AND_UNSHARE
		x_pam_syslog ( pam, LOG_ERR, "unsharing: invalid argument: \"%s\" (see \"man 2 pam_ns\")", arg );
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
		*user_gid_p = user->pw_gid;

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
	PROCTAB *proc = openproc ( 0 );
	proc_t proc_info;
	memset ( &proc_info, 0, sizeof ( proc_info ) );
	uid_t user_uid = -1;
	gid_t user_gid = -1;

	if ( pam_get_uidgid ( pam, flags, &user_uid, &user_gid ) != PAM_SUCCESS )
		return PAM_SYSTEM_ERR;

	while ( readproc ( proc, &proc_info ) != NULL ) {
		//x_pam_syslog ( pam, LOG_INFO, "proc info: tid == %u; uid == %u; gid == %u (searching for: %i; %u; %u)", proc_info.tid, proc_info.euid, proc_info.egid, groupby, user_uid, user_gid );
		switch ( groupby ) {
			case GB_USER:
				if ( proc_info.euid == user_uid ) {
					return ns_attach ( pam, flags, &proc_info, argc, argv );
				}

				break;

			case GB_GROUP:
				if ( proc_info.egid == user_gid ) {
					return ns_attach ( pam, flags, &proc_info, argc, argv );
				}

				break;

			default:
				return PAM_SYSTEM_ERR;
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
				int rc_ns;
#ifdef LOCKS
				struct sembuf sb;
				int semid;
				int rc;
				x_pam_syslog ( pam, LOG_INFO, "locking via semaphores" );

				if ( ( rc = ns_lock ( &sb, &semid ) ) ) {
					x_pam_syslog ( pam, LOG_ERR, "internal error: cannot setup semaphores (rc == %u)", rc );
					return PAM_SESSION_ERR;
				}

#endif
				rc_ns = ns_find_attach ( pam, flags, groupby, argc, argv );

				switch ( rc_ns ) {
					case PAM_SESSION_ERR:					// if didn't found where to attach to
						rc_ns = ns_detach ( pam, flags, argc, argv );	// then just detach from current namespaces
						break;

					case PAM_SUCCESS:
						break;

					default:
						x_pam_syslog ( pam, LOG_ERR, "internal error: unknown return code from ns_find_attach(): %u", rc_ns );
						break;
				}

#ifdef LOCKS
				x_pam_syslog ( pam, LOG_INFO, "unlocking via semaphores" );

				if ( ( rc = ns_unlock ( &sb, &semid ) ) ) {
					x_pam_syslog ( pam, LOG_ERR, "internal error: cannot free semaphores (rc == %u)", rc );
					return PAM_SESSION_ERR;
				}

#endif
				return rc_ns;
			}

		default: {
			} // anti-warning
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
			x_pam_syslog ( pam, LOG_ERR, "invalid argument: \"%s\" (see \"man 2 pam_ns\"; should be \"session\", \"user\" or \"group\")", arg );
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
