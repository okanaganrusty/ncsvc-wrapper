#define _GNU_SOURCE

#define DEFAULT_BUFFER_SIZE 512

int IGNORE_ALL_NETWORK = 0; 

// Lets store the default gateway and ignore adding any routes against it.
static char TUNNEL_INTERFACE_NAME[DEFAULT_BUFFER_SIZE];

static const char *DEFAULT_IGNORE_TARGETS[] =
  {
    "169.254.0.0",
    "0.0.0.0",
    NULL
  };

static FILE *f_logfile;
static void dbg_log(char const *, ...);
static void fail(char const *, ...);
static void warn(char const *, ...);
static int check_environment(char *, void *);

static int (*real_ioctl)(int, int, void*);

void librtwrap_init() __attribute__((constructor));

typedef struct ignore_target {
  struct sockaddr_in network;
  struct ignore_target *next;
} ignore_target_t;

typedef struct add_target { 
  struct sockaddr_in network;
  struct sockaddr_in netmask;
  struct add_target *next;
} add_target_t;

ignore_target_t *ignore_target_head; 
ignore_target_t *ignore_target_tail;

add_target_t *add_target_head;
add_target_t *add_target_tail;

