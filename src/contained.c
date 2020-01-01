#define _GNU_SOURCE
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

#define STCK_SIZE (1024 * 1024)
#define USERNS_OFFSET 10000
#define USERNS_COUNT 2000

#define cleanup()   if (sockets[0]) close(sockets[0]); \
                    if (sockets[1]) close(sockets[1]);\
                    return err;
#define usage()     fprintf(stderr, "Usage: %s -u -l -m . -c /bin/sh ~\n", argv[0]);
#define error()     err = 1;
#define finish_options()    if (!config.argc) usage();\
                            if (!config.mountDir) usage();\
                            char hostName[256] = {0};\
                            if (chooseHostname(hostName, sizeof(hostName))) error();\
                            config.hostName = hostName;\
                            cleanup();
#define clearResources()    freeResurces(&config);\
                            free(stack);



struct childConfig {
    int argc;
    uid_t uid;
    int fd;
    char *hostName;
    char **argv;
    char *mountDir;
};

int handleChildUIDMap(pid_t childPID, int fd)
{
    int uidMap = 0;
    int hasUserns = -1;

    if (read(fd, &hasUserns, sizeof(hasUserns)) != sizeof(hasUserns))   
    {
        fprintf(stderr, "couldnt read child\n");
        return -1;
    }

    if (hasUserns)
    {
        char path[PATH_MAX] = {0};

        for (char **file = (char*[]) { "uidMapm", "gidMap", 0 }; *file; file++)
        {
            if (snprintf(path, sizeof(path), "/proc/%d/%s", childPID, *file) > sizeof(path))
            {
                fprintf(stderr, "snprintf too big ? %m\n");
                return -1;
            }

            fprintf(stderr, "writing %s...", path);

            if ((uidMap = open(path, O_WRONLY)) == -1)
            {
                fprintf(stderr, "open failed: %m\n");
                return -1;
            }

            if (dprintf(uidMap, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1)
            {
                fprintf(stderr, "dprintf failed: %m\n");
                close(uidMap);
                return -1;
            }

            close(uidMap);
        }

        if (write(fd, &(int){0}, sizeof(int)) != sizeof(int))
        {
            fprintf(stderr, "couldnt write: %m\n");
            return -1;
        }
    }

    return 0;
}

int userns(struct childConfig *cnf)
{
    fprintf(stderr, "=> trying a user namespace");
    
    int hasUserns = !unshare(CLONE_NEWUSER);
    int result = 0;

    if (write(cnf->fd, &hasUserns, sizeof(hasUserns)) != sizeof(hasUserns))
    {
        fprintf(stderr, "couldnt write: %m\n");
        return -1;
    }

    if (read(cnf->fd, &result, sizeof(result)) != sizeof(resources))
    {
        fprintf(stderr, "couldnt read: %m\n");
        return -1;
    }

    if (result) return -1;

    hasUserns ? fprintf(stderr, "done\n"):fprintf(stderr, "unsupported? continuing\n");}

    fprintf(stderr, "switching to uid %d / gid %d", cnf->uid, cnf->uid);

    if (setgroups(1, &(gid_t){ cnf->uid}) || setresgid(cnf->uid, cnf->uid, cnf->uid) ||
    setresuid(cnf->uid, cnf->uid, cnf->uid))
    {
        fprintf(stderr, "%m\n");
        return -1;
    }

    fprintf(stderr, "done\n");
    return 0;
}

int freeResurces(struct childConfig *config)
{
    return 0;
}

int resources(struct childConfig *config)
{
    return 0;
}

int mounts(struct cildConfig *config) 
{
    // TODO: создать времены и вложеный в него каталог, сонтировать корень во внутрений каталог, во время завершения работы сделать umount и удалить каталоги
    return 0;
}

int capabilities()
{
    return 0;
}

int child(void *arg)
{
    struct childConfig *cnf = arg;

    if (sethostname(cnf->hostName, strlen(cnf->hostName)) || mount(cnf) || userns(cnf)
    || capabilities() || syscall())
    {
        close(cnf->fd);
        return -1;
    }

    if (close(cnf->fd))
    {
        fprintf(stderr, "close failed: %m\n");
        return -1;
    }

    if (execve(cnf->argv[0], cnf->argv, NULL))
    {
        fprintf(stderr, "execve failed %m\n");
        return -1;
    }

    return 0;
}

int chooseHostname(char *buffer, size_t len)
{
    static const char *suits[] = {"ta", "za", "sho"};
    static const char *minor[] = {"ace", "two", "three"};
    static const char *major[] = {"fool", "magician", "high-priestess"};

    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    size_t ix = now.tv_nsec % 78;

    if (ix < sizeof(major) / sizeof(*major))
    {
        snprintf(buffer, len, "%0ldx-%s", now.tv_sec, major[ix]);
    }
    else {
        ix -= sizeof(major) / sizeof(*major);
        snprintf(buffer, len, "%05lxc-%s-of-%s", now.tv_sec, minor[ix % (sizeof(minor) / sizeof(*minor))], suits[ix / (sizeof(minor) / sizeof(*minor))]);
    }
    return 0;
}

int main(int argc, char **argv)
{
    int err = 0;
    int option = 0;
    int lastOptind = 0;
    int sockets[2] = { 0 };
    int flags = CLONE_NEWNS
		| CLONE_NEWCGROUP
		| CLONE_NEWPID
		| CLONE_NEWIPC
		| CLONE_NEWNET
		| CLONE_NEWUTS;
    pid_t childPID = 0;
    struct childConfig config = { 0 };   

    // Обработка параметров 
    while ((option = getopt(argc, argv, "a:m:u:")) != -1)
    {
        switch (option)
        {
            case 'c':
                config.argc = argc - lastOptind - 1;
                config.argv = &argv[argc - config.argc];
                
                finish_options();
            case 'm':
                config.mountDir = optarg;
                break;
            case 'u':
                if (sscanf(optarg, "%d", &config.uid) != 1)
                {
                    fprintf(stderr, "badly-formatted uid: %s\n", optarg);
                    usage();
                }
                break;
            default:
                usage();
        }
        lastOptind = optind;
    }

    //проверка версии ос
    fprintf(stderr, "=> calidating Linux version...");
    // создаем экземпляр структуры в которой определена информация о ОС и обнуляем его 
    struct utsname host = { 0 };
    // записываем системную информацию в наш экземпляр
    if (uname(&host))
    {
        fprintf(stderr, "failed: %m\n");
        cleanup();
    }

    int major = -1;
    int minor = -1;
    // записываем первые два значений релиза ядра в переменные 
    if (sscanf(host.release, "%u.%u", &major, &minor) != 2)
    {
        fprintf(stderr, "weird release format: %s\n", host.release);
        cleanup();
    }

    // проверяем версию ядра
    if (major != 5 || (minor != 0))
    {
        fprintf(stderr, "expected 5.0.x %s\n", host.release);
        cleanup();
    }

    // проверяем работает ли ОС на арх х86_64 
    if (strcmp("x86_64", host.machine))
    {
        fprintf(stderr, "expected x86_64: %s\n", host.machine);
        cleanup();
    }

    fprintf(stderr, "%s on %s\n", host.release, host.machine);

    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets))
    {
        fprintf(stderr, "socketpair failed: %m\n");
        error();
    }

    if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC))
    {
        fprintf(stderr, "fcntl failed: %m\n");
        error();
    }
    
    config.fd = sockets[1];
    char *stack = 0;

    if (!(stack = malloc(STCK_SIZE)))
    {
        fprintf(stderr, "=> malloc failed, out of memory?\n");
        error();
    }

    if (resources(&config))
    {
        err = 1;
        cleanup();
    }

    if ((childPID = clone(child, stack + STCK_SIZE, flags | SIGCHLD, &config)) == -1)
    {
        fprintf(stderr, "=> clone failed %m\n");
        err = 1;
        clearResources();
    }

    close(sockets[1]);
    sockets[1] = 0;

    return 0;
}