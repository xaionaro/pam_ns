```
NAME
       pam_unshare - an unshare() PAM module

SYNOPSIS
       session optional pam_unshare.so [...]

DESCRIPTION
       pam_unshare.so  is  a PAM module, that calls unshare(2) with speci‐
       fied argument.

OPTIONS
       Possible options are:
              CLONE_FILES
              CLONE_FS
              CLONE_NEWIPC
              CLONE_NEWNET
              CLONE_NEWNS
              CLONE_NEWPID
              CLONE_NEWUSER
              CLONE_NEWUTS
              CLONE_SYSVSEM

       For details read unshare(2).

EXAMPLES
       session optional pam_unshare.so CLONE_NEWIPC CLONE_NEWNS

AUTHOR
       Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C

SUPPORT
       You can get support on IRC-channel  in  Freenode  "#clsync"  or  on
       github's issue tracking system of

SEE ALSO
       unshare(2), pam(3)
```

See an alternative: [scraperwiki/pam_unshare](https://github.com/scraperwiki/pam_unshare)
