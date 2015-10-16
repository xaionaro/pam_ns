```
NAME
       pam_ns - an unshare()/setns() PAM module

SYNOPSIS
       session optional pam_ns.so <session|user|group> <...>

DESCRIPTION
       pam_ns.so is a PAM module, that calls unshare(2) with specified
       argument.

       The first argument defines the strategy. Possible values:
              session
                     Just call unshare(2) on every new session.
              user
                     Call unshare(2) on creating the first user session. If
                     the  session  is  not the first then connect to names‐
                     paces of an already existing session using setns(2).
              group
                     Call unshare(2) on creating the first session  of  any
                     user  of  the  group.  If the session is not the first
                     then connect to namespaces of an already existing ses‐
                     sion using setns(2).

       Warning!   Modes user and group uses semaphores (sem_overview(7)) to
       prevent race conditions and requires for the module to be  installed
       to  "/lib/security/pam_ns.so"  to  work  properly due to a hack
       with ftok(3) in it's code.

       The search of an appropriate process (to get  namespaces  to  attach
       to)  is  performed  by  scanning  /proc  (see proc(5)).  The "/proc"
       should be mounted to get this plugin work properly.

OPTIONS
       Possible options are:
              CLONE_NEWIPC
              CLONE_NEWNET
              CLONE_NEWNS
              CLONE_NEWPID
              CLONE_NEWUSER
              CLONE_NEWUTS

       For details read unshare(2).

EXAMPLES
       session optional pam_ns.so user CLONE_NEWIPC CLONE_NEWNS

AUTHOR
       Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C

SUPPORT
       You can get support on  IRC-channel  in  Freenode  "#clsync"  or  on
       github's issue tracking system of the pam_ns repository.

SEE ALSO
       unshare(2), setns(2), pam(3), proc(5), sem_overview(7) ftok(3)
```

See an alternative: [scraperwiki/pam_unshare](https://github.com/scraperwiki/pam_unshare)

Build dependencies (in Debian terms): `libpam0g-dev libprocps3-dev`
