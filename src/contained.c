#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <linux/limits.h>

struct childConfig {
    int argc;
    uid_t uid;
    int fd;
    char *hostName;
    char **argv;
    char *mountDir;
};

int chooseHostname(char *buffer, size_t len)
{
    return 5;
}



int main(int argc, char **argv)
{
    int err = 0;
    int option = 0;
    int lastOptind = 0;
    int sockets[2] = { 0 };
    struct childConfig config = { 0 };   

    // Обработка параметров 
    while ((option = getopt(argc, argv, "a:m:u:")) != -1)
    {
        switch (option)
        {
            case 'c':
                config.argc = argc - lastOptind - 1;
                config.argv = &argv[argc - config.argc];
                goto finish_options;
            case 'm':
                config.mountDir = optarg;
                break;
            case 'u':
                if (sscanf(optarg, "%d", &config.uid) != 1)
                {
                    fprintf(stderr, "badly-formatted uid: %s\n", optarg);
                    goto usage;
                }
                break;
            default:
                goto usage;
        }
        lastOptind = optind;
    }

    fprintf(stderr, "=> calidating Linux version...");
    struct utsname host = { 0 };
    if (uname(&host))
    {
        fprintf(stderr, "failed: %m\n");
        goto cleanup;
    }

    int major = -1;
    int minor = -1;

    if (sscanf(host.release, "%u.%u", &major, &minor) != 2)
    {
        fprintf(stderr, "weird release format: %s\n", host.release);
        goto cleanup;
    }

    if (major != 4 || (minor != 7 && minor != 8))
    {
        fprintf(stderr, "expected 4.7.x or 4.8.x: %s\n", host.release);
        goto cleanup;
    }

    if (strcmp("X86_64", host.machine))
    {
        fprintf(stderr, "expected X86_64: %s\n", host.machine);
        goto cleanup;
    }

    fprintf(stderr, "%s on %s.\n", host.release,host.machine);

    finish_options:
        if (!config.argc) goto usage;
        if (!config.mountDir) goto usage;
        char hostName[256] = {0};
        if (chooseHostname(hostName, sizeof(hostName)))
            goto error;
        config.hostName = hostName;
 
        goto cleanup;

    usage:
        fprintf(stderr, "Usage: %s -u -l -m . -c /bin/sh ~\n", argv[0]);

    error:
        err = 1;
    
    cleanup:
        if (sockets[0]) close(sockets[0]);
        if (sockets[1]) close(sockets[1]);
        return err;

    
    return 0;
}