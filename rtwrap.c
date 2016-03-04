/*
 * This file intercepts SIOCADDRT and SIOCDELRT ioctl() calls.
 *
 * It silently ignores requests for specific routes.
 */
#define _GNU_SOURCE

#include <net/route.h>
#include <linux/sockios.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/*
 * Routes for the specified addresses are silently ignored.
 */

typedef struct ignore_target {
    char addr[64];
    struct sockaddr_in sa;
    struct ignore_target *next;
} ignore_target_t;

typedef struct add_target { 
    char network[64];
    char mask[64];
     
    struct add_target *next;
} add_target_t;

struct ignore_target *ignore_target_head; 
struct ignore_target *ignore_target_tail;
struct add_target *add_target_head;
struct add_target *add_target_tail;

static const char *DEFAULT_IGNORE_TARGETS[] =
{
    "208.57.223.4",
    "172.16.41.0",
    "172.16.40.0",
    "169.254.0.0",
    "0.0.0.0",
    NULL
};

static FILE *f_logfile;
static int (*real_ioctl)(int, int, void*);

void librtwrap_init() __attribute__((constructor));

static void
dbg_log(char const *fmt, ...)
{
    va_list ap;

    if (f_logfile == NULL)
        return;

    va_start(ap, fmt);
    vfprintf(f_logfile, fmt, ap);
    va_end(ap);

    fprintf(f_logfile, "\n");
    fflush(f_logfile);
}

static void
fail(char const *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "rtwrap: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\nrtwrap: Aborting\n");
    abort();
}


struct ignore_target *append_ignore_target(const char *addr) {
	struct ignore_target *ignore_target_ptr;
	struct ignore_target *t;

	ignore_target_ptr = ignore_target_head;

	while (ignore_target_ptr->next != ignore_target_tail) {
          ignore_target_ptr = ignore_target_ptr->next;
        }

     	t = (struct ignore_target *) malloc(sizeof *t);
         
        if (addr != NULL && strncpy(t->addr, addr, strlen(addr))) {
	  t->next = ignore_target_tail;

	  ignore_target_ptr->next = t;
        }

	return ignore_target_ptr;
}
	
struct add_target *append_add_target(char *addr) {
	struct add_target *add_target_ptr;
	struct add_target *t;
        char *token = NULL;

        int pos = 0;

	add_target_ptr = add_target_head;

	while (add_target_ptr->next != add_target_tail) {
          add_target_ptr = add_target_ptr->next;
        }

     	t = (struct add_target *) malloc(sizeof *t);

        while ((token = strsep(&addr, ":"))) {
          if (pos == 0) 
            strncpy(t->network, token, strlen(token));
          else if (pos == 1)
            strncpy(t->mask, token, strlen(token));

          pos++;
        }

	t->next = add_target_tail;

	add_target_ptr->next = t;

	return add_target_ptr;
}
	
int ignore_target_exists_str(const char *addr) { 
    struct ignore_target *ignore_target_ptr;

    ignore_target_ptr = ignore_target_head->next;

    while (ignore_target_ptr != ignore_target_tail) {
      if (strncmp(addr, ignore_target_ptr->addr, strlen(ignore_target_ptr->addr)) == 0) { 
        return 1;
      }

      ignore_target_ptr = ignore_target_ptr->next;
    }

    return 0;
}

int ignore_target_exists(struct sockaddr_in const *sa) { 
    struct ignore_target *ignore_target_ptr = ignore_target_head; 

    // ignore_target_ptr = ignore_target_head->next;

    while (ignore_target_ptr != ignore_target_tail) {
      if (sa->sin_addr.s_addr == ignore_target_ptr->sa.sin_addr.s_addr) {
        dbg_log("rtwrap: match %s and %s, target exists", inet_ntoa(sa->sin_addr), inet_ntoa(ignore_target_ptr->sa.sin_addr)); 
        return 1;
      }

      ignore_target_ptr = ignore_target_ptr->next;
    }

    return 0;
}

static int
route_wrapper(int fd, int request, struct rtentry *entry)
{
    if (entry->rt_dst.sa_family != AF_INET)
        return real_ioctl(fd, request, entry);

    struct sockaddr_in const *dst_addr = (struct sockaddr_in const *)&entry->rt_dst;

    /*
    dbg_log("rtwrap: request to add route to network (1/3) %s", inet_ntoa(((struct sockaddr_in *)(&entry->rt_dst))->sin_addr));
    dbg_log("rtwrap: request to add route to mask (2/3) %s", inet_ntoa(((struct sockaddr_in *)(&entry->rt_genmask))->sin_addr));
    dbg_log("rtwrap: request to add route to gateway (3/3) %s", inet_ntoa(((struct sockaddr_in *)(&entry->rt_gateway))->sin_addr));
    */

    /* 
     * Periodically add missing routes defined by RTWRAP_ADD (taking the destination gateway from dst_addr)
     * RTWRAP_ADD=172.30.0.0:255.255.0.0
     */
     
    struct add_target *add_target_ptr = add_target_head;

    add_target_ptr = add_target_head->next;

    while (add_target_ptr != add_target_tail) { 
      struct rtentry route;
      struct sockaddr_in 
        *network,
        *mask,
        *gateway;

      memset(&route, 0, sizeof(route));

      int rtfd = socket(AF_INET, SOCK_DGRAM, 0);

      // Network address
      network = (struct sockaddr_in *)(&route.rt_dst);
      network->sin_family = AF_INET;
      network->sin_addr.s_addr = inet_addr(add_target_ptr->network);
      network->sin_port = 0;

      // Network mask
      mask = (struct sockaddr_in *)(&route.rt_genmask);
      mask->sin_family = AF_INET;
      mask->sin_addr.s_addr = inet_addr(add_target_ptr->mask);
      mask->sin_port = 0;
    
      // Gateway
      gateway = (struct sockaddr_in *)(&route.rt_gateway);
      gateway->sin_addr.s_addr = inet_addr(inet_ntoa(((struct sockaddr_in *)(&entry->rt_gateway))->sin_addr));
      gateway->sin_family = AF_INET;
      gateway->sin_port = 0;
      
      route.rt_flags = RTF_UP | RTF_GATEWAY;
      route.rt_metric = 1;

      int err;

      // We could check if the route exists already before trying to add ...
      // but I really don't feel like it.

      if ((err = real_ioctl(rtfd, SIOCADDRT, &route)) != 0) {
        perror("SIOCADDRT failed");
      }

      close(rtfd);

      add_target_ptr = add_target_ptr->next;
    }

    /*
     * Silently ignore requests to the specified ignore_targets
     */

    struct ignore_target *ignore_target_ptr;

    ignore_target_ptr = ignore_target_head->next;

    while (ignore_target_ptr != ignore_target_tail) {
      if (ignore_target_exists(dst_addr) == 1) {
        dbg_log("rtwrap: ignoring request to %s route for %s", 
          request == SIOCADDRT ? "add" : "delete", 
          inet_ntoa(dst_addr->sin_addr));

        return 0;
      }

      ignore_target_ptr = ignore_target_ptr->next;
    }

    return real_ioctl(fd, request, entry);
}

int
ioctl(int fd, int request, void *arg)
{
    if (request == SIOCADDRT || request == SIOCDELRT)
        return route_wrapper(fd, request, arg);

    return real_ioctl(fd, request, arg);
}

void
librtwrap_init()
{
    /*
     * Enable debug logging when the RTWRAP_LOG environment variable is set
     */
    if (getenv("RTWRAP_LOG") != NULL)
    {
        /*
         * We don't take the logfile path from the environment,
         * since that would be a giant security hole.
         */
        char const *LOGFILE_PATH = "/tmp/rtwrap.log";
        f_logfile = fopen(LOGFILE_PATH, "a");
        if (f_logfile == NULL)
            fail("failed to open debug log file \"%s\"", LOGFILE_PATH);
    }

    dbg_log("rtwrap starting at %ld", (long)time(NULL));

    /*
     * Initialize the list
     */

    struct ignore_target *ignore_target_ptr;
    struct add_target *add_target_ptr;

    ignore_target_head = (struct ignore_target *) malloc(sizeof *ignore_target_head);
    ignore_target_tail = (struct ignore_target *) malloc(sizeof *ignore_target_tail);

    ignore_target_head->next = ignore_target_tail;
    ignore_target_tail->next = ignore_target_tail;

    add_target_head = (struct add_target *) malloc(sizeof *add_target_head);
    add_target_tail = (struct add_target *) malloc(sizeof *add_target_tail);

    add_target_head->next = add_target_tail;
    add_target_tail->next = add_target_tail;

    /* 
     * Add to the list of ignored networks via environment variable
     */

    unsigned int i = 0;
    char *ignore = NULL;
    char *token = NULL;
     
    for (i = 0; i < (sizeof(DEFAULT_IGNORE_TARGETS) / sizeof(DEFAULT_IGNORE_TARGETS[0])); i++) { 
      if (DEFAULT_IGNORE_TARGETS[i] == NULL) 
        continue;

      if (!ignore_target_exists_str(DEFAULT_IGNORE_TARGETS[i])) {
        dbg_log("rtwrap: appending default ignore ignore targets to list %s", DEFAULT_IGNORE_TARGETS[i]);
        ignore_target_ptr = append_ignore_target(DEFAULT_IGNORE_TARGETS[i]);
      }
    }
 
    if ((ignore = (char *) getenv("RTWRAP_IGNORE")) != NULL) { 
      while ((token = strsep(&ignore, ","))) {
        if (!ignore_target_exists_str(token)) {
         dbg_log("rtwrap: appending environmental ignore targets to list %s", token);
         ignore_target_ptr = append_ignore_target(token);
        }
      }
    }

    if ((ignore = (char *) getenv("RTWRAP_IGNORE")) != NULL) { 
      while ((token = strsep(&ignore, ","))) {
        if (!ignore_target_exists_str(token)) {
         dbg_log("rtwrap: appending environmental force targets to list %s", token);
         ignore_target_ptr = append_ignore_target(token);
        }
      }
    }

    if ((ignore = (char *) getenv("RTWRAP_ADD")) != NULL) { 
      while ((token = strsep(&ignore, ","))) {
         dbg_log("rtwrap: appending environmental add targets to list %s", token);
         add_target_ptr = append_add_target(token);
      }
    }

    /*
     * Unset the LD_PRELOAD environment variable.
     * Our wrapper library only needs to be loaded for ncsvc itself,
     * not other programs that it execs.
     *
     * (Furthermore, ncsvc is a 32-bit executable so our wrapper library is
     * too.  However, on 64-bit systems it execs some 64-bit programs, can't
     * load our 32-bit library, causing an error message from the loader.)
     */
    unsetenv("LD_PRELOAD");

    /*
     * Look up the address for the real ioctl() call
     */
    real_ioctl = dlsym(RTLD_NEXT, "ioctl");
    if (real_ioctl == NULL)
        fail("failed to find real ioctl() function");

    ignore_target_ptr = ignore_target_head->next;

    while (ignore_target_ptr != ignore_target_tail) {
      ignore_target_ptr->sa.sin_family = AF_INET;
      ignore_target_ptr->sa.sin_port = htons(0);

      inet_aton(ignore_target_ptr->addr, &ignore_target_ptr->sa.sin_addr);

      ignore_target_ptr = ignore_target_ptr->next;
    }
}
