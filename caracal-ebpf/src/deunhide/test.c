#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sched.h>
#include <signal.h>
#include <sys/resource.h>




#include <time.h>
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);

    char path[100];

    struct stat buffer;
    sprintf(path, "/proc/%d", pid);
    int ret =stat(path,&buffer);
    printf("stat /proc/%d return %d\n",pid, ret);

    sprintf(path,"/proc/%d/status",pid);
    ret =stat(path,&buffer);
    printf("stat /proc/%d/status return %d\n",pid, ret);

    sprintf(path,"/proc/%d",pid);
    ret = chdir(path);
    printf("chdir /proc/%d return %d\n",pid, ret);

    sprintf(path,"/proc/%d/task",pid);
    ret = chdir(path);
    printf("chdir /proc/%d/task return %d\n",pid, ret);

    ret = getsid(pid);
    printf("sid return %d\n", ret);

    cpu_set_t mask;
    ret = getpgid(pid);
    printf("getpgid return %d\n", ret);
    
    ret = kill(pid,0);
    printf("kill return %d\n", ret);

    struct sched_param param;
    ret = sched_getparam(pid, &param);
    printf("sched_getparam return %d\n", ret);

    ret = sched_getscheduler(pid);
    printf("sched_getscheduler return %d\n", ret);

    struct timespec tp;
    ret = sched_rr_get_interval(pid, &tp);
    printf("sched_rr_get_interval return %d\n", ret);

    int which = PRIO_PROCESS;
    ret = getpriority(which,pid);
    printf("getpriority return %d\n", ret);

    return 0;
}