/*
 * This file intercepts SIOCADDRT and SIOCDELRT ioctl() calls.
 *
 * It silently ignores requests for specific routes.
 */

#define _GNU_SOURCE

#include <net/route.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "rtwrap.h"

int check_environment(char *header, void *ptr) 
{ 
  char *data;

  if ((data = getenv(header)) == NULL) 
    return 0;
   
  if (sizeof(data) * strlen(data) > DEFAULT_BUFFER_SIZE) { 
    warn("exceeded buffer size while reading environment variable '%s'", header);
    return 0;
  }

  if (ptr) {
    strncpy(ptr, data, strlen(data));
  }
 
  return 1;
}

static void dbg_log(char const *fmt, ...) 
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

static void fail(char const *fmt, ...) 
{
  va_list ap;

  fprintf(stderr, "rtwrap: ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fprintf(stderr, "\nrtwrap: aborting\n");
  abort();
}

static void warn(char const *fmt, ...)
{
  va_list ap;

  fprintf(stderr, "rtwrap: warning: ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

ignore_target_t *append_ignore_target(char *target) 
{
  ignore_target_t *t;
  ignore_target_t *ignore_target_ptr = ignore_target_head;

  while (ignore_target_ptr->next != ignore_target_tail) {
    ignore_target_ptr = ignore_target_ptr->next;
  }

  t = (ignore_target_t *) malloc(sizeof *t);
         
  if (target) {
    inet_pton(AF_INET, target, &t->network.sin_addr);

    t->network.sin_port = htons(0);
    t->network.sin_family = AF_INET;
    t->next = ignore_target_tail;

    ignore_target_ptr->next = t;
  }

  return ignore_target_ptr;
}
	
add_target_t *append_add_target(char *addr) 
{
  add_target_t *add_target_ptr;
  add_target_t *t;
  char *token = NULL;

  int pos = 0;

  add_target_ptr = add_target_head;

  while (add_target_ptr->next != add_target_tail) {
    add_target_ptr = add_target_ptr->next;
  }

  t = (add_target_t *) malloc(sizeof *t);
  t->network.sin_port = htons(0);
  t->network.sin_family = AF_INET;
  t->netmask.sin_port = htons(0);
  t->netmask.sin_family = AF_INET;

  while ((token = strsep(&addr, ":"))) {
    (pos == 0) ? 
      inet_pton(AF_INET, token, &t->network.sin_addr)
      : inet_pton(AF_INET, token, &t->netmask.sin_addr);
   
    pos++;
  }

  t->next = add_target_tail;

  add_target_ptr->next = t;

  return add_target_ptr;
}
	
int ignore_target_exists(struct sockaddr_in *sa) 
{ 
  char sa_address[32] = { 0 };
  char ignore_address[32] = { 0 };

  ignore_target_t *ignore_target_ptr = ignore_target_head->next;

  inet_ntop(AF_INET, (struct in_addr *)(&sa->sin_addr.s_addr), sa_address, 32);
 
  while (ignore_target_ptr != ignore_target_tail) {
    inet_ntop(AF_INET, (struct in_addr *)(&ignore_target_ptr->network.sin_addr.s_addr), ignore_address, 32);

    if (strncmp(sa_address, ignore_address, strlen(ignore_address)) == 0) { 
      return 1; 
    }

    ignore_target_ptr = ignore_target_ptr->next;
  }

  return 0;
}

/*
static int 
interface_wrapper(int fd, int request, struct ifreq *entry) { 
  int iffd;
  struct ifreq *if_req = entry;

  iffd = socket(AF_INET, SOCK_DGRAM, 0);
  close(iffd);

  printf("interface name: %s\n", if_req->ifr_ifrn.ifrn_name);

  return real_ioctl(fd, request, entry);
}
*/

static int
route_wrapper(int fd, int request, struct rtentry *entry)
{
  char network_address[32] = { 0 };
  char network_mask[32] = { 0 };

  char rt_network_address[32] = { 0 };
  char rt_gateway_address[32] = { 0 };
  char rt_network_mask[32] = { 0 };

  int err;

  if (entry->rt_dst.sa_family != AF_INET)
    return real_ioctl(fd, request, entry);

  struct rtentry route;

  struct sockaddr_in *rt_gateway = (struct sockaddr_in *) &entry->rt_gateway;
  struct sockaddr_in *rt_network = (struct sockaddr_in *) &entry->rt_dst;
  struct sockaddr_in *rt_netmask = (struct sockaddr_in *) &entry->rt_genmask;

  inet_ntop(AF_INET, (struct in_addr *)(&rt_gateway->sin_addr.s_addr), rt_gateway_address, 32);
  inet_ntop(AF_INET, (struct in_addr *)(&rt_network->sin_addr.s_addr), rt_network_address, 32);
  inet_ntop(AF_INET, (struct in_addr *)(&rt_netmask->sin_addr.s_addr), rt_network_mask, 32);

  add_target_t *add_target_ptr = add_target_head->next;

  while (add_target_ptr != add_target_tail) { 
    // Gateway
    struct sockaddr_in gateway;

    memset(&route, 0, sizeof(struct rtentry));
    memset(&gateway, 0, sizeof(struct sockaddr_in));

    int rtfd = socket(AF_INET, SOCK_DGRAM, 0);

    gateway.sin_addr.s_addr = rt_gateway->sin_addr.s_addr;
    gateway.sin_family = AF_INET;
    gateway.sin_port = htons(0);

    ((struct sockaddr_in *) &route.rt_dst)->sin_family = AF_INET;
    ((struct sockaddr_in *) &route.rt_dst)->sin_port = htons(0);
    ((struct sockaddr_in *) &route.rt_dst)->sin_addr.s_addr = add_target_ptr->network.sin_addr.s_addr;

    ((struct sockaddr_in *) &route.rt_genmask)->sin_family = AF_INET;
    ((struct sockaddr_in *) &route.rt_genmask)->sin_port = htons(0);
    ((struct sockaddr_in *) &route.rt_genmask)->sin_addr.s_addr = add_target_ptr->netmask.sin_addr.s_addr;

    inet_ntop(AF_INET, (struct in_addr *)(&add_target_ptr->network.sin_addr.s_addr), network_address, 32);
    inet_ntop(AF_INET, (struct in_addr *)(&add_target_ptr->netmask.sin_addr.s_addr), network_mask, 30);

    memcpy((void *) &route.rt_gateway, &gateway, sizeof(gateway));

    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_metric = 1;

    dbg_log("rtwrap: %s route %s/%s via %s", 
      (request == SIOCADDRT ? "adding" : "removing"), 
      network_address, network_mask, rt_gateway_address);

    if ((err = real_ioctl(rtfd, request, &route)) != 0) {
      perror("ioctl");
    }

    close(rtfd);

    add_target_ptr = add_target_ptr->next;
  }

  /*
   * Silently ignore requests to the specified ignore_targets
   */

  dbg_log("rtwrap: received route request for %s/%s via %s", rt_network_address, rt_network_mask, rt_gateway_address);

  if (IGNORE_ALL_NETWORK && (request == SIOCADDRT || request == SIOCDELRT)) {
    dbg_log("rtwrap: ignoring route request because we are ignoring all pushed routes");
    return 0;
  }

  if (ignore_target_exists(rt_network)) {
    return 0;
  }

  return real_ioctl(fd, request, entry);
}

int
ioctl(int fd, int request, void *arg)
{
  if (request == SIOCADDRT || request == SIOCDELRT)
    return route_wrapper(fd, request, arg);

  /*
  if (request == SIOCSIFADDR || request == SIOCGIFADDR || request == SIOCDIFADDR)
    return interface_wrapper(fd, request, arg);
  */

  return real_ioctl(fd, request, arg);
}

void
librtwrap_init()
{
  unsigned int i = 0;
  char buffer[DEFAULT_BUFFER_SIZE] = { 0 };
  char *token;
  char *ptr;
  
  /*
   * Enable debug logging when the RTWRAP_LOG environment variable is set
   */

  if (check_environment("RTWRAP_LOG", NULL)) 
    {
      /*
       * We don't take the logfile path from the environment,
       * since that would be a giant security hole.
       */

      char *ABSOLUTE_LOG_FILE = "/tmp/rtwrap.log";
 
      f_logfile = fopen(ABSOLUTE_LOG_FILE, "a");

      if (f_logfile == NULL) {
	fail("failed to open debug log file \"%s\"", ABSOLUTE_LOG_FILE);
      }
    }

  dbg_log("rtwrap: starting at %ld", (long)time(NULL));

  memset(&buffer, 0, sizeof(buffer));

  if (check_environment("RTWRAP_IGNORE_ALL_NETWORK", &buffer)) {    
    IGNORE_ALL_NETWORK = atoi(buffer);
    
    if (IGNORE_ALL_NETWORK < 0 || IGNORE_ALL_NETWORK > 1) { 
      /* Assume it's always 1 if it's set, but the value is unknown */
      IGNORE_ALL_NETWORK = 1;
    }
  }
  
  if (!IGNORE_ALL_NETWORK) {
    dbg_log("rtwrap: allowing route additions");
    
    /*
     * Initialize the list
     */

    ignore_target_head = (ignore_target_t *) malloc(sizeof *ignore_target_head);
    ignore_target_tail = (ignore_target_t *) malloc(sizeof *ignore_target_tail);

    ignore_target_head->next = ignore_target_tail;
    ignore_target_tail->next = ignore_target_tail;

    /* 
     * Add to the list of ignored networks via environment variable
     */
     
    for (i = 0; i < (sizeof(DEFAULT_IGNORE_TARGETS) / sizeof(DEFAULT_IGNORE_TARGETS[0])); i++) { 
      if (DEFAULT_IGNORE_TARGETS[i] == NULL) 
        continue;
    }
 
    memset(&buffer, 0, DEFAULT_BUFFER_SIZE);

    if (check_environment("RTWRAP_IGNORE_NETWORK", &buffer)) { 
      ptr = buffer;

      while ((token = strsep(&ptr, ","))) {
        dbg_log("rtwrap: appending environmental ignore targets to list %s", token);
        printf("rtwrap: appending environmental ignore targets to list %s\n", token);
        append_ignore_target(token);
      }
    }
  } else {
    dbg_log("rtwrap: ignoring all routes");
  }

  memset(&buffer, 0, DEFAULT_BUFFER_SIZE);

  if (check_environment("RTWRAP_ADD_NETWORK", &buffer)) { 
    add_target_head = (add_target_t *) malloc(sizeof *add_target_head);
    add_target_tail = (add_target_t *) malloc(sizeof *add_target_tail);
    add_target_head->next = add_target_tail;
    add_target_tail->next = add_target_tail;

    ptr = buffer;

    while ((token = strsep(&ptr, ","))) {
      dbg_log("rtwrap: appending environmental add targets to list %s", token);
      append_add_target(token);
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
}
