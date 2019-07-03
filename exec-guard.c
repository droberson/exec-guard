#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <dlfcn.h>
#include <limits.h>
#include <sys/types.h>
#include <linux/limits.h>


int execve(const char *progname, char *const argv[], char *const envp[]) {
  int		(*original_execve)(const char *, char *const[], char *const[]);
  FILE		*fp;
  int		i;
  char		loginuid[PATH_MAX];
  char		buf[LINE_MAX];
  uid_t		uid = -1;
  int		commandlen;
  size_t	len;
  pid_t		ppid;
  int		found = 0;
  char		basepath[PATH_MAX];

  /* Add/remove whitelisted paths here. */
  char		*valid_paths[] = { "/bin", "/sbin", "/usr/bin", "/usr/sbin" };


  ppid = getppid();
  openlog("exec-logger", LOG_PID, LOG_AUTHPRIV);

  sprintf(loginuid, "/proc/%d/loginuid", getppid());

  fp = fopen(loginuid, "r");
  if (fp == NULL) {
    syslog(LOG_WARNING, "ERROR: Couldn't open /proc/%d/loginuid", ppid);
  } else {
    if (fscanf(fp, "%d", &uid) != 1) {
      syslog(LOG_WARNING, "ERROR: Couldn't read /proc/%d/loginuid", ppid);
      uid = -1;
    }

    fclose(fp);
  }

  /* Only need the path, so replace last / character with NULL */
  strncpy(basepath, progname, sizeof(basepath));
  for(i = strlen(basepath); basepath; i--) {
    if (basepath[i] == '/') {
      basepath[i] = '\0';
      break;
    }
  }

  /* Check if path exists in our valid list.. */
  for (found = 0, i = 0; i < sizeof(valid_paths) / sizeof(char *); i++) {
    if (strcmp(basepath, valid_paths[i]) == 0) {
      found = 1;
      break;
    }
  }

  if (found != 1) {
    syslog(LOG_INFO, "INVALID PATH: %s (%s)", basepath, progname);
    return -1;
  }

  sprintf(buf, "[UID:%d PARENT_PID:%d] CMD:", uid, ppid);
  commandlen = strlen(buf);

  for (i = 0; argv[i] != NULL; i++) {
    len = strlen(argv[i]);

    /* Adding more to the buffer will overflow it, break the loop */
    /* TODO: inform the log that output has been truncated */
    if ((commandlen + 1 + len) >= LINE_MAX)
      break;

    buf[commandlen++] = ' ';
    strcpy(buf + commandlen, argv[i]);
    commandlen += len;
  }

  syslog(LOG_INFO, "%s", buf);

  *(void **)(&original_execve) = dlsym(RTLD_NEXT, "execve");  
  return((*original_execve)(progname, argv, envp));
}
