# exec-guard

This is an LD_PRELOAD library that will intercept execve() calls and
only run them if the path is in a whitelist defined within
exec-guard.c

Failed attempts will be logged to syslog(). Successful runs will also
be logged.

## Installation

	$ make
	$ sudo cp exec-guard.so /usr/lib
	$ sudo vi /etc/ld.so.preload ## add a line: "/usr/lib/exec-guard.so"

