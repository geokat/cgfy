#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <getopt.h>
#include <libcgroup.h>

#define CGNAME_MAX_LEN 64

static void usage(const char *name)
{
    printf("Usage: %s [OPTIONS] [COMMAND]\n", name);
    printf("  -n, --max-cgroups=N\n"
            "\t\tSet maximum number of cgroups.\n");
    printf("  -r, --use-existing-cgroups\n"
            "\t\tIf suggested cgroup already exists (i.e. a user's task is\n"
            "\t\talready running), assign the new task to that cgroup; the\n"
            "\t\tdefault is to reject new tasks from already active users.\n");
    printf("  -m, --memory-limit=N\n"
            "\t\tSet memory limit for each task in bytes.\n");
    printf("  -s, --memsw-limit=N\n"
            "\t\tSet memsw (memory+swap) limit for each task in bytes.\n");
    printf("  -u, --user=USER\n"
            "\t\tRun the task as user USER. The default is to run as root.\n");
    printf("  -c, --cpuset-cpus=<0[-N][,M]>\n"
            "\t\tSet the cpuset.cpus parameter (required if the cpuset\n"
            "\t\tsubsystem is mounted).\n");
    printf("  -e, --cpuset-mems=<0[-N][,M]>\n"
            "\t\tSet the cpuset.mems parameter (required if the cpuset\n"
            "\t\tsubsystem is mounted).\n");
    printf("  -h, --help\n"
            "\t\tDisplay this help message.\n");
}

int main (int argc, char *argv[])
{
    int ret, use_existing = 0;
    uint max = 0, memlim = 0, swplim = 0;
    uid_t uid;
    gid_t gid;
    char cgname[CGNAME_MAX_LEN];

    const struct passwd *pwd = NULL;
    char *cpus = NULL, *mems = NULL;
    struct cgroup *cgroup = NULL;

    static struct option long_opts[] = {
        {"max-cgroups", required_argument, NULL, 'n'},
        {"use-existing-cgroups", no_argument, NULL, 'r'},
        {"memory-limit", required_argument, NULL, 'm'},
        {"memsw-limit", required_argument, NULL, 's'},
        {"user", required_argument, NULL, 'u'},
        {"cpuset-cpus", required_argument, NULL, 'c' },
        {"cpuset-mems", required_argument, NULL, 'e' },
        {"help", no_argument, NULL, 'h' },
        {0, 0, 0, 0},
    };

    /* No parameters on input. */
    if (argc < 2) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    while ((ret = getopt_long(argc, argv, "n:rm:s:u:c:e:h", long_opts, NULL))
           > 0) {
        switch (ret) {
        case 'n':
            max = atoi(optarg);
            break;
        case 'r':
            use_existing = 1;
            break;
        case 'm':
            memlim = atoi(optarg);
            break;
        case 's':
            swplim = atoi(optarg);
            break;
        case 'u':
            errno = 0;
            /* This can point to a static area; do not pass to free()! */
            if(!(pwd = getpwnam(optarg))) {
                if (errno)
                    perror("getpwnam");
                else
                    fprintf(stderr,
                            "%s: user %s does not exist\n",
                            argv[0], optarg);
                exit(EXIT_FAILURE);
            }
            uid = pwd->pw_uid;
            gid = pwd->pw_gid;
            break;
        case 'c':
            if (!(cpus = malloc(strlen(optarg) + 1))) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }
            strcpy(cpus, optarg);
            break;
        case 'e':
            if (!(mems = malloc(strlen(optarg) + 1))) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }
            strcpy(mems, optarg);
            break;
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
            break;
        }
    }

    /* Sanity check. */
    if (optind >= argc) {
        fprintf(stderr, "%s: no command to run.\n", argv[0]);
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (!max || (cpus && !mems) || (!cpus && mems)) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (memlim && swplim && swplim <= memlim) {
        fprintf(stderr, "%s: memsw-limit <= memory-limit.\n", argv[0]);
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Read the suggested cgroup name (e.g. an IP address) from stdin. */
    while (((ret = read(0, cgname, CGNAME_MAX_LEN - 1)) == -1)
           && (errno == EINTR)) {}
    cgname[ret] = '\0';

    /* initialize libcgroup */
    ret = cgroup_init();
    if (ret) {
        fprintf(stderr,
                "%s: libcgroup initialization failed: %s\n",
                argv[0], cgroup_strerror(ret));
        goto err;
    }

    /* See if we should start the new task. Use the number of existing cgroups
     * and the --use-existing-cgroups option to decide. */
    void *handle;
    struct cgroup_file_info info;
    int lvl, count = 0, found = 0;

    ret = cgroup_walk_tree_begin("memory", "/", 0, &handle, &info, &lvl);
    if (ret != 0) {
        fprintf(stderr, "%s: failed to enumerate existing cgroups\n", argv[0]);
        goto err;
    }
    while (cgroup_walk_tree_next(0, &handle, &info, lvl) != ECGEOF) {
        if (info.type == CGROUP_FILE_TYPE_DIR) {
            if (!strcmp(cgname, info.path))
                found = 1;
            count++;
        }
    }
    cgroup_walk_tree_end(&handle);

    if (found && !use_existing) {
        puts("alreadyExists");
        exit(EXIT_SUCCESS);
    }
    if (count >= max && !found) {
        puts("maxedOut");
        exit(EXIT_SUCCESS);
    }

    cgroup = cgroup_new_cgroup(cgname);
    if (!cgroup) {
        ret = ECGFAIL;
        fprintf(stderr, "%s: failed to construct cgroup: %s\n",
                argv[0], cgroup_strerror(ret));
        goto err;
    }

    struct cgroup_controller *cgc = cgroup_add_controller(cgroup, "memory");
    if (!cgc) {
        ret = ECGINVAL;
        fprintf(stderr, "%s: failed to add memory controller\n",
                argv[0]);
        goto err;
    }

    if (!found) {
        if (cgroup_add_value_bool(cgc, "notify_on_release", 1)) {
            fprintf(stderr,
                    "%s: failed to set notify_on_release for cgroup\n", argv[0]);
            goto err;
        }
        if (memlim &&
            cgroup_add_value_uint64(cgc, "memory.limit_in_bytes", memlim)) {
            fprintf(stderr,
                    "%s: failed to set memory limit for cgroup\n", argv[0]);
            goto err;
        }
        if (swplim &&
            cgroup_add_value_uint64(cgc, "memory.memsw.limit_in_bytes", swplim)) {
            fprintf(stderr,
                    "%s: failed to set memsw limit for cgroup\n", argv[0]);
            goto err;
        }
        /* If the cpuset subsystem is mounted, the following two parameters must be
           set explicitly, otherwise trying to move a task into the new cgroup will
           fail with "No space on device". We leave it up to the user to make sure
           they provide the parameters if needed. */
        if (cpus || mems) {
            if (cgroup_add_value_string(cgc, "cpuset.cpus", cpus)) {
                fprintf(stderr,
                        "%s: failed to set cpuset.cpus for cgroup\n", argv[0]);
                goto err;
            }
            if (cgroup_add_value_string(cgc, "cpuset.mems", mems)) {
                fprintf(stderr,
                        "%s: failed to set cpuset.mems for cgroup\n", argv[0]);
                goto err;
            }
        }

        ret = cgroup_create_cgroup(cgroup, 1);
        if (ret) {
            fprintf(stderr, "%s: failed to create cgroup %s: %s\n",
                    argv[0], cgname, cgroup_strerror(ret));
            goto err;
        }
    }

    ret = cgroup_attach_task_pid(cgroup, getpid());
    if (ret) {
        fprintf(stderr, "%s: failed to assign new task to cgroup: %s\n",
                argv[0], cgroup_strerror(ret));
        goto err;
    }

    /* Clean up */
    if (cgroup) cgroup_free(&cgroup);
    if (cpus) free(cpus);
    if (mems) free(mems);

    /* Switch to running as requested user. */
    if (pwd) {
        if (setgroups(1, &gid)) { perror("setgroups"); goto err; }
        if (setregid(gid, gid)) { perror("setregid"); goto err; }
        if (setreuid(uid, uid)) { perror("setreuid"); goto err; }
        if (setgid(gid))        { perror("setgid"); goto err; }
        if (setuid(uid))        { perror("setuid"); goto err; }
    }

    execve(argv[optind], argv + optind, NULL);
    perror("execve");

err:
    puts("error");
    if (cgroup) cgroup_free(&cgroup);
    if (cpus) free(cpus);
    if (mems) free(mems);
    exit(EXIT_FAILURE);
}

/*
 * Local variables:
 * compile-command: "gcc -lcgroup -o cgfy cgfy.c && ./cgfy":
 * End:
 */
