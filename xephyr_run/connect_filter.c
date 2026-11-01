/* connect-filter [--allow REGEX | --deny REGEX]... -- COMMAND [ARGS...]
 *
 * Runs COMMAND with every connect() it makes decided by the ordered rules. A rule's regular
 * expression (POSIX extended) is matched against the target: "@name" for an abstract Unix socket,
 * the canonical absolute path for a Unix path socket. The first matching rule wins. Anything that
 * matches no rule, and every non-Unix address, is allowed.
 *
 * The decision is made on a copy of the address read once from the program's memory. If allowed,
 * this supervisor performs the connect itself on the program's own socket, using that same copy,
 * so the program cannot change the address between the check and the use. See connect_filter.py
 * for the limits of this approach; this is the compiled equivalent of its Python supervisor.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <pthread.h>
#include <regex.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

#if defined(__x86_64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
#else
#error "connect-filter supports x86_64 and aarch64 only"
#endif

#define MAX_RULES 256
#define SOCKADDR_MAX 128
#define UNIX_PATH_MAX 108

struct rule {
    int allow;
    regex_t pattern;
};

static struct rule rules[MAX_RULES];
static int rule_count;
static int listener = -1;
static volatile pid_t child;

static void usage(void)
{
    fputs("usage: connect-filter [--allow REGEX | --deny REGEX]... -- COMMAND [ARGS...]\n", stderr);
    exit(2);
}

static int install_filter(void)
{
    struct sock_filter program[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef __x86_64__
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_setup, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog fprog = { sizeof program / sizeof program[0], program };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
}

/* Send text, and a descriptor if fd >= 0, over a Unix socket. */
static void send_message(int sock, int fd, const char *text)
{
    struct iovec iov = { (void *)text, strlen(text) };
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1 };

    if (fd >= 0) {
        memset(control, 0, sizeof control);
        message.msg_control = control;
        message.msg_controllen = sizeof control;
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &fd, sizeof(int));
    }
    sendmsg(sock, &message, 0);
}

/* Receive a descriptor, or -1 with the sender's explanation in text. */
static int receive_message(int sock, char *text, size_t size)
{
    struct iovec iov = { text, size - 1 };
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control,
                              .msg_controllen = sizeof control };
    ssize_t got = recvmsg(sock, &message, 0);

    text[got > 0 ? got : 0] = '\0';
    if (got <= 0)
        return -1;
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS)
        return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(header), sizeof(int));
    return fd;
}

static int read_memory(pid_t pid, uint64_t address, void *buffer, size_t size)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/mem", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -EFAULT;
    ssize_t got = pread(fd, buffer, size, (off_t)address);
    close(fd);
    return got == (ssize_t)size ? 0 : -EFAULT;
}

static int allowed_by_rules(const char *name)
{
    for (int i = 0; i < rule_count; i++)
        if (regexec(&rules[i].pattern, name, 0, NULL, 0) == 0)
            return rules[i].allow;
    return 1;
}

/* Decide on a copied address. Returns 0 to allow, with the sockaddr to connect to in target,
 * or -errno. Unix path addresses are replaced by their canonical path so the connect goes to
 * exactly what was judged. */
static int judge(pid_t pid, const unsigned char *raw, size_t length, unsigned char *target,
                 size_t *target_length)
{
    char name[SOCKADDR_MAX + 2];
    uint16_t family;

    memcpy(&family, raw, sizeof family);
    memcpy(target, raw, length);
    *target_length = length;
    if (family != AF_UNIX)
        return 0;

    const unsigned char *body = raw + 2;
    size_t body_length = length - 2;
    if (body_length > 0 && body[0] == 0) {
        if (memchr(body + 1, 0, body_length - 1))
            return -ECONNREFUSED;   /* a NUL inside a name cannot be matched faithfully */
        name[0] = '@';
        memcpy(name + 1, body + 1, body_length - 1);
        name[body_length] = '\0';
    } else {
        size_t path_length = strnlen((const char *)body, body_length);
        if (path_length == 0) {
            name[0] = '\0';
        } else {
            char text[SOCKADDR_MAX + 1], joined[PATH_MAX * 2 + 2], resolved[PATH_MAX];
            memcpy(text, body, path_length);
            text[path_length] = '\0';
            if (text[0] == '/') {
                snprintf(joined, sizeof joined, "%s", text);
            } else {
                char link[64], directory[PATH_MAX];
                snprintf(link, sizeof link, "/proc/%d/cwd", (int)pid);
                ssize_t got = readlink(link, directory, sizeof directory - 1);
                if (got < 0)
                    return -errno;
                directory[got] = '\0';
                snprintf(joined, sizeof joined, "%s/%s", directory, text);
            }
            if (!realpath(joined, resolved))
                return -errno;
            size_t resolved_length = strlen(resolved);
            if (resolved_length >= UNIX_PATH_MAX)
                return -ENAMETOOLONG;
            memcpy(name, resolved, resolved_length + 1);
            memcpy(target, &family, sizeof family);
            memcpy(target + 2, resolved, resolved_length + 1);
            *target_length = 2 + resolved_length + 1;
        }
    }
    if (allowed_by_rules(name))
        return 0;
    /* A refused abstract socket looks like one nobody listens on: X libraries try the abstract
     * name first and only fall back to the file socket on ECONNREFUSED or ENOENT, not EACCES. */
    return name[0] == '@' ? -ECONNREFUSED : -EACCES;
}

/* Connect the program's own socket (the same open file description) to address. */
static int connect_for(pid_t pid, int descriptor, const void *address, socklen_t length)
{
    int result = 0;
    int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pidfd < 0)
        return -errno;
    int duplicate = (int)syscall(SYS_pidfd_getfd, pidfd, descriptor, 0);
    if (duplicate < 0) {
        result = -errno;
    } else {
        if (connect(duplicate, address, length) < 0)
            result = -errno;
        close(duplicate);
    }
    close(pidfd);
    return result;
}

static void reply(uint64_t id, int error)
{
    struct seccomp_notif_resp response;
    memset(&response, 0, sizeof response);
    response.id = id;
    response.error = error;
    ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response);   /* fails only if nobody is waiting */
}

static void *handle(void *argument)
{
    struct seccomp_notif *notification = argument;
    uint64_t id = notification->id;
    pid_t pid = (pid_t)notification->pid;
    int descriptor = (int)notification->data.args[0];
    uint64_t pointer = notification->data.args[1];
    uint64_t length = notification->data.args[2];
    unsigned char raw[SOCKADDR_MAX], target[SOCKADDR_MAX];
    size_t target_length;
    int error;

    if (length < 2 || length > SOCKADDR_MAX) {
        error = -EINVAL;
    } else if ((error = read_memory(pid, pointer, raw, length)) == 0) {
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) != 0)
            goto done;
        error = judge(pid, raw, length, target, &target_length);
        if (error == 0)
            error = connect_for(pid, descriptor, target, (socklen_t)target_length);
    }
    reply(id, error);
done:
    free(notification);
    return NULL;
}

static void forward_signal(int number)
{
    if (child > 0)
        kill(child, number);
}

static int finish(int status)
{
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

int main(int argc, char **argv)
{
    int i = 1;

    for (; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        int allow = strcmp(argv[i], "--allow") == 0;
        if ((!allow && strcmp(argv[i], "--deny") != 0) || i + 1 >= argc || rule_count == MAX_RULES)
            usage();
        rules[rule_count].allow = allow;
        int failure = regcomp(&rules[rule_count].pattern, argv[++i], REG_EXTENDED | REG_NOSUB);
        if (failure) {
            char message[128];
            regerror(failure, &rules[rule_count].pattern, message, sizeof message);
            fprintf(stderr, "connect-filter: bad regular expression '%s': %s\n", argv[i], message);
            return 2;
        }
        rule_count++;
    }
    if (i >= argc)
        usage();

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
        perror("connect-filter: socketpair");
        return 1;
    }
    child = fork();
    if (child < 0) {
        perror("connect-filter: fork");
        return 1;
    }
    if (child == 0) {
        close(pair[0]);
        int filter = install_filter();
        if (filter < 0) {
            send_message(pair[1], -1, strerror(errno));
            _exit(1);
        }
        send_message(pair[1], filter, "ok");
        close(filter);
        close(pair[1]);
        execvp(argv[i], &argv[i]);
        perror(argv[i]);
        _exit(127);
    }

    close(pair[1]);
    char text[256];
    listener = receive_message(pair[0], text, sizeof text);
    close(pair[0]);
    if (listener < 0) {
        int status;
        waitpid(child, &status, 0);
        fprintf(stderr, "connect-filter: could not install the filter: %s\n", text);
        return 1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = forward_signal;
    action.sa_flags = SA_RESTART;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);

    for (;;) {
        int status;
        if (waitpid(child, &status, WNOHANG) == child)
            return finish(status);
        struct pollfd watch = { listener, POLLIN, 0 };
        int ready = poll(&watch, 1, 100);
        if (ready > 0 && (watch.revents & POLLIN)) {
            struct seccomp_notif *notification = calloc(1, sizeof *notification);
            if (notification && ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, notification) == 0) {
                pthread_t thread;
                if (pthread_create(&thread, NULL, handle, notification) == 0) {
                    pthread_detach(thread);
                    continue;
                }
            }
            free(notification);
        } else if (ready > 0 && (watch.revents & (POLLHUP | POLLERR))) {
            waitpid(child, &status, 0);
            return finish(status);
        }
    }
}
