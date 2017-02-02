TODO: Threads, ...


#netinet/in.h
- includes
  - `sys/socket.h`
  - `machine/endian.h`
  - `stdint.h (uint{8,16,32} types)`

- defines options for use with [gs]etsockopt at the IP level

- fines INADDR_str
  INADDR_ANY       (u_int32_t)0x00000000
  INADDR_BROADCAST (u_int32_t)0xffffffff
  INADDR_LOOPBACK  (u_int32_t)0x7f000001
  INADDR_NONE      0xFFFFFFFF (return -1)

- defines IPPROTO_str
  IPPROTO_RAW       255 (0xFF)
  IPPROTO_IP        0
  IPPROTO_HOPOPTS   0
  IPPROTO_ICMP      1
  IPPROTO_IGMP      2
  IPPROTO_IPV4      4
  IPPROTO_IPIP      IPPROTO_IPV4
  IPPROTO_TCP       6
  IPPROTO_EGP       8 (exterior gateway protocol)
  IPPROTO_PIGP      9 (private interior gateway protocol)
  IPPROTO_UDP       17
  IPPROTO_IPV6      41
  IPPROTO_SCTP      132

- notes:
  0-1023 => well known ports
  1024-49151 => Registered ports
  49152-65535 => Dynamic and/or private ports
  INET_ADDRSTRLEN 16

- defines structs:
  in_addr:
    ```c
    struct in_addr {
      in_addr_t s_addr;
    }
    ```
  sockaddr_in: (socket address, internet style)
    ```c
    struct sockaddr_in {
      __uint8_t sin_len;
      sa_family_t sin_family;
      in_port_t sin_port;
      struct in_addr sin_addr;
      char sin_zero[8];
    }

    ```
- advanced:IP options: (ip options, for use with get/setsockopt at IP level)
  IP_OPTIONS 1 -- get ip options
  IP_HDRINCL 2 -- include header with data
  IP_TOS 3     -- ip type of serviceand reced
  IP_TTL 4     -- IP time to live
  IP_MULTICASE_IF 9   -- set/get ip multicast interface
  IP_MULTICAST_TTL 10 -- set/get ip multicast ttl
  IP_RSVP_ON 15 -- enable rsvp in kernel (16 to disable)
  IP_BOUND_IF   -- set/get bound interface
  IP_FW_ADD 40, DEL 41, FLUSH 42, ZERO 43, GET 4, RESETLOG 45


-------------------------------------------------------------------------------


#netdb.h
- includes:
  `stdint.h`
  `netinet/in.h`

- externs:
  h_errno

- h_errno error codes:

  Error codes from gethostbyname() / gethostbyaddr()
    HOST_NOT_FOUND  1. authoritative answer host not found
    TRY_AGAIN       2, non-authoritative host not found, or servfail
    NO_RECOVERY     3, non recoverable errors (former, refused, notimp)
    NO_DATA         4, valid name no data
  Error codes from getaddrinfo
    EAI_AGAIN       2, temp failure in resolving name
    EAI_BADFLAGS    3, invalid value in ai_flags
    EAI_FAIL        4, failure in name resolution
    EAI_FAMILY      5, unsupported ai_family
    EAI_MEMORY      6, memory allocation failure
    EAI_NONAME      8, host or servname not known
    EAI_SERVICE     9, servname
    EAI_SOCKTYPE    10, ai_socktype not supported
    EAI_SYSTEM      11, system error returnedin errno
    EAI_OVERFLOW    14, argument buffer overflow

- getaddrinfo flags:
  AI_PASSIVE      0x00000001 -- get addr to use bind
  AI_CANONNAME    0x00000002 -- fill canonical name
  AI_NUMERICHOST  0x00000004 -- prevent resolution
  AI_NUMERICSERV  0x00001000 -- prevent name resolution

- function prototypes:
  ```c
  #include <netdb.h>

  struct protoent *
  getprotoent(void);

  struct protoent *
  getprotobyname(const char *name);

  struct protoent *
  getprotobynumber(int proto);

  void
  setprotoent(int stayopen);

  void
  endprotoent(void);


  struct servent *
  getservent();

  struct servent *
  getservbyname(const char *name, const char *proto);

  struct servent *
  getservbyport(int port, const char *proto);

  void
  setservent(int stayopen);

  void
  endservent(void);


  int
  getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host,
    socklen_t hostlen, char *serv, socklen_t servlen, int flags);

  int
  getaddrinfo(const char *hostname, const char *servname,
    const struct addrinfo *hints, struct addrinfo **res);

  void
  freeaddrinfo(struct addrinfo *ai);

  struct netent *
  getnetent(void);

  struct netent *
  getnetbyname(const char *name);

  struct netent *
  getnetbyaddr(uint32_t net, int type);

  void
  setnetent(int stayopen);

  void
  endnetent(void);

  const char *
  gai_strerror(int ecode);

  struct hostent *
  gethostbyname(const char *name);

  struct hostent *
  gethostbyname2(const char *name, int af);

  struct hostent *
  gethostbyaddr(const void *addr, socklen_t len, int type);

  struct hostent *
  gethostent(void);

  void
  sethostent(int stayopen);

  void
  endhostent(void);

  void
  herror(const char *string);

  const char *
  hstrerror(int err);

  struct hostent *
  getipnodebyname(const char *name, int af, int flags, int *error_num);

  struct hostent *
  getipnodebyaddr(const void *src, size_t len, int af, int *error_num);

  void
  freehostent(struct hostent *ptr);
  ```

- defines the following structs:
  netent:
    ```c
    // assumes that network num fits in unsigned long :(
    struct netent {
      char *n_name;       // official name
      char **nn_aliases;  // alias list
      int n_addrtype;     // net address type
      uint32_t n_net;     // network
    }
    ```
  servent:
    ```c
    struct servent {
      char *s_name;     // official service name
      char **s_aliases; // aliases list
      int p_proto;      // protocol
    }
    ```
  protoent:
    ```c
    struct protoent {
      char *p_name;     // official protocol name
      char **p_aliases; // alias list
      int p_proto;      // protocol
    }
    ```
  addrinfo:
    ```c
    // linked list:
    struct addrinfo {
      int ai_flags;             // AI_{PASSIVE,CANONNAME,NUMERICHOST}
      int ai_family;            // PF_xxx
      int ai_socktype;          // SOCK_xxx
      int ai_protocol           // 0 or IPPROTO_xxx for IPv{4,6}
      socklen_t ai_addrlen;     // length of ai_addr
      char     *ai_canonname;   // canonical name
      struct sockaddr *ai_addr; // binary address
      struct addrinfo *ai_next; // next list item or null
    ```
  hostent:
```c
struct hostent {
  char   *h_name;         // official name of host
  char  **h_aliases;›     // alias list
  int     h_addrtype;›    // host address type
  int     h_length;       // length of address
  char  **h_addr_list;›   // list of addresses from name server
  h_addr  h_addr_list[0]› // address, for backward compatibility
};
```

-------------------------------------------------------------------------------


#arpa/inet.h
- includes:
  sys/cdefs.h
  stdint.h
  machine/endian.h
  netinet/in.h

- Defines the following functions:
```c
     char *
     addr2ascii(int af, const void *addrp, int len, char *buf);

     int
     ascii2addr(int af, const char *ascii, void *result);

     in_addr_t
     inet_addr(const char *cp);

     int
     inet_aton(const char *cp, struct in_addr *pin);

     in_addr_t
     inet_lnaof(struct in_addr in);

     struct in_addr
     inet_makeaddr(in_addr_t net, in_addr_t lna);

     in_addr_t
     inet_netof(struct in_addr in);

     in_addr_t
     inet_network(const char *cp);

     char *
     inet_ntoa(struct in_addr in);

     char *
     inet_ntoa_r(struct in_addr in, char *buf, socklen_t size);

     const char *
     inet_ntop(int af, const void * restrict src, char * restrict dst, socklen_t size);

     int
     inet_pton(int af, const char * restrict src, void * restrict dst);
```

-------------------------------------------------------------------------------

#unistd.h
- implements the posix/single unix specification standard

- includes:
  sys/unistd.h
  Availability.h
  select.h

- functions like:
  ```
  _exit()
  access()
  alarm()
  chdir()
  chown()
  dup()
  dup2()
  execl()
  execle()
  execlp()
  execv()
  execve()
  execvp()
  fork()
  fpathconf()
  getcwd()
  getegid()
  geteuid()
  getgid()
  getgroups()
  setgroups()
  getlogin()
  getpid()
  getpgrp()
  getppid()
  getuid()
  isatty()
  link()
  lseek()
  pathconf()
  pause()
  pipe()
  read()
  rmdir()
  setgid()
  setpgid()
  setsid()
  setuid()
  sleep()
  sysconf()
  ttyname()
  ttyname_r()
  unlink()
  write()
  getopt() <-- arg parsing
  brk()
  chroot()
  crypt()
  ctermid()
  encrypt()
  gethostid()
  getpgid()
  getsid()
  getpagesize()
  gettablesize()
  getpass()
  getwd()
  lchown()
  lockf()
  nice()
  pread()
  pwrite()
  sbrk()
  setregid()
  setreuid()
  swab() <-- swap adjacent bytes
  sync()
  truncate()
  ualarm()
  usleep()
  vfork()
  fsync()
  ftruncate()
  fchown()
  gethostname()
  readlink()
  symlink()
  acct()
  getgrouplist()
  getmode()
  getpeerid()
  mkdtemp()
  mktemp()
  mkstemp()
  swapon()
  ttyslot()
  valloc()
  syscall()
  getsubopt()
  ```


-------------------------------------------------------------------------------


#sys/fcntl.h: defines file stuff
- Definitions:

  Opening files:
    O_RDONLY   0x0000
    O_WRONLY   0x0001
    O_RDWR     0x0002
    O_ACCMODE  0x0003  (mask for above modes)
    O_NONBLOCK 0x0004  (no delay)
    O_APPEND   0x0008  (set append mode)
    O_SHLOCK   0x0010  (open with shared lock)
    O_EXLOCK   0x0020  (open with exclusive lock)
    O_ASYNC    0x0040  (signal pgrp when data ready)
    O_NOFOLLOW 0x0100  (dont follow symlinks)
    O_CREAT    0x0200  (create if nonexistant)
    O_TRUNC    0x0400  (truncate to zero)
    O_EXCL     0x0800  (error if exists)
    O_CLOEXEC  0x10000000 (explicitly set FD_CLOEXEC)

  Constants used for fcntl(2):
    F_DUPFD           0  (duplicate file descriptor)
    F_GETFD           1  (get fd flags)
    F_SETFD           2  (set fd flags)
    F_GETFL           3  (get file status flags)
    F_SETFL           4  (set file status flags)
    F_GETOWN          5  (get SIGIO/SIGURG proc/pgrp)
    F_SETOWN          6  (set SIGIO/SIGURG proc/pgrp)
    F_GETLK           7  (get record locking info)
    F_SETLK           8  (set record locking info)
    F_SETLKW          8  (F_SETLK; wait if blocked)
    F_FLUSH_DATA      40
    F_CHKCLEAN        41 (used for regression testing)
    F_PREALLOCATE     42 (preallocate storage)
    F_SETSIZE         43 (truncate a file without zeroing space)
    F_RDADVISE        44 (issue an advisory read async with no copy to user)
    F_RDAHEAD         45 (turn read ahead on/off for this fd)
    F_NOCACHE         48 (turn data caching on/off for this fd)
    F_LOG2PHYS        49 (file offset to device offset)
    F_GETPATH         50 (return the full path of the fd)
    F_FULLSYNC        51 (fsync + asyk the drive to flush to the media)
    F_PATHPKG_CHECK   52 (find which component is a package)
    F_FREEZE_FS       53 (freeze all fs operations)
    F_THAW_FS         54 (thaw all fs operations)
    F_GLOBAL_NOCACHE  55 (turn data caching on/off globally for this file)
    F_NODIRECT        62 (used in conjunction with F_NOCACHE to indicate that
                          DIRECT, synchronous writes should not be used but its
                          ok to temporarily create cached pages)
    F_GETLKPID        66 (get process level record locking info)

  File descriptor flags:
    FD_CLOEXEC  1 (close-on-exec flag)

  Record locking flags:
    F_RDLOCK    1 (shared / read lock)
    F_UNLCK     2 (unlock)
    F_WRLCK     3 (exclusive / write lock)

- Structs:
```
struct flock {
  off_t l_start;    // starting offset
  off_t l_len;      // len = 0 means until end offile
  pid_t l_pid;      // lock owner
  short l_type;     // lock type: read,write, etc
  short l_whence;   / type of l_start
}

struct flocktimeout {
  struct flock    fl;       // flock passed for file lockign
  struct timespec timeout;  // timespec struct for timeout
}

struct radvisory {
  off_t ra_offset;
  int   ra_count;
}
```

- Lock operations for flock():
  LOCK_SH    0x01 (shared file lock)
  LOCK_EX    0x02 (exclusive lock)
  LOCK_NB    0x04 (dont block when locking)
  LOCK_UN    0x08 (unlock file)

- Functions:
  open()
  openat()
  creat()
  fcntl()
  flock();



-------------------------------------------------------------------------------


#sys/un.h
- socket options:
  LOCAL_PEERCRED    0x001 (retrieve peer creds)
  LOCAL_PEERPID     0x002 (retrieve peer id)
  LOCAL_PEEREPID    0x003 (retrieve eff peer pid)
  LOCAL_PEERUUID    0x004 (retrieve peer uuid)
  LOCAL_PEEREUUID   0x005 (retrieve eff peer uuid)

- get/setsockopt level number for local domain sockets:
  SOL_LOCAL   0

- structs:
```
struct sockaddr_un {
  unsigned char sun_len;      // sockaddr len including null
  sa_family_t sun_family;    // AF_UNIX
  char        sun_path[104]; // pathname (gag)
}
```


-------------------------------------------------------------------------------


#sys/socket.h
- includes:
  sys/types.h
  sys/cdefs.h
  net/net_kev.h

- Types of sockets:
  SOCK_STREAM     1 (stream)
  SOCK_DGRAM      2 (datagram)
  SOCK_RAW        3 (raw-protocol interface)
  SOCK_SEQPACKET  5 (sequenced packet stream)

- Option flags per socket:
  [standard]:
    SO_DEBUG          0x0001 (turn on debugging info recording)
    SO_ACCEPTCON      0x0002 (socket has had listen())
    SO_REUSEADDR      0x0004 (allow local address reuse)
    SO_KEEPALIVE      0x0008 (keep connections alive)
    SO_DONTROUTE      0x0010 (just use the interface addresses)
    SO_BROADCAST      0x0020 (permit sending of broadcast msgs)
    SO_LINGER         0x0080 (linger on close if data present (in ticks OSX)
                              - linux val: 0x1080(seconds in linux)
    SO_OOBLINE        0x0100 (leave received oob data in line)
  [nonstandard]:
    SO_REUSEPORT      0x0200 (use the same port and local address)
    SO_TIMESTAMP      0x0400 (timestamp received dgram traffic)
    SO_NUMRCVPKT      0x1112 (number of pkts in recv queue/socket buffer)

- other:
    SOL_SOCKET        0xFFFF (options for socket)
                             (level number for get/setsocktopt()  to apply
                              to socket itself)

- Address families: [note: protocol familys just reference address families]
  AF_UNSPEC   0 (unspecified)
  AF_UNIX     1 (local to host [pipes])
  AF_INET     2 (internetwork: UDP,TCP,etc)
  AF_INET6    30 (IPv6)
  AF_SYSTEM   32 (kernel event msgs)
  AF_NETBIOS  33 (NetBIOS)
  AF_PPP      34 (PPP comm protocol)

- socket options:
  SO_DEBUG        enables recording of debugging information
  SO_REUSEADDR    enables local address reuse
  SO_REUSEPORT    enables duplicate address and port bindings
  SO_KEEPALIVE    enables keep connections alive
  SO_DONTROUTE    enables routing bypass for outgoing messages
  SO_LINGER       linger on close if data present
  SO_BROADCAST    enables permission to transmit broadcast messages
  SO_OOBINLINE    enables reception of out-of-band data in band
  SO_SNDBUF       set buffer size for output
  SO_RCVBUF       set buffer size for input
  SO_SNDLOWAT     set minimum count for output
  SO_RCVLOWAT     set minimum count for input
  SO_SNDTIMEO     set timeout value for output
  SO_RCVTIMEO     set timeout value for input
  SO_NOSIGPIPE    do not generate SIGPIPE, instead return EPIPE
  SO_LINGER_SEC   linger on close if data present with timeout in seconds
  [getonly]:
  SO_NREAD        number of bytes to be read
  SO_NWRITE       number of bytes written not yet sent by the protocol
  SO_TYPE         get the type of the socket
  SO_ERROR        get and clear error on the socket


- functions:
```c

int
accept(
int socket, struct sockaddr *restrict address, socklen_t *restrict address_len
)

int
bind(
int socket, const struct sockaddr *address, socklen_t address_len
)

int
connect(
int socket, const struct sockaddr *address, socklen_t address_len
)

int
getpeername(
int socket, struct sockaddr *restrict address, socklen_t *restrict address_len
)

int
getsockname(
nt socket, struct sockaddr *restrict address,
         socklen_t *restrict address_len
)

int
getsockopt(
int socket, int level, int option_name, void *restrict option_value,
         socklen_t *restrict option_len
)

int
listen(
int socket, int backlog
)


ssize_t
recv(
int socket, void *buffer, size_t length, int flags
)

ssize_t
recvfrom(
int socket, void *restrict buffer, size_t length, int flags,
         struct sockaddr *restrict address, socklen_t *restrict address_len
)

ssize_t
recvmsg(
int socket, struct msghdr *message, int flags
)

ssize_t
send(
int socket, const void *buffer, size_t length, int flags
)

ssize_t
sendmsg(
int socket, const struct msghdr *message, int flags
)

ssize_t
sendto(
int socket, const void *buffer, size_t length, int flags,
         const struct sockaddr *dest_addr, socklen_t dest_len
)

int
setsockopt(
nt socket, int level, int option_name, const void *option_value,
         socklen_t option_len
)

int
shutdown(
int socket, int how
)

int
sockatmark(
)

int
socket(
int domain, int type, int protocol
)

int
socketpair(
int domain, int type, int protocol, int socket_vector[2]
)

int
sendfile(
int fd, int s, off_t offset, off_t *len, struct sf_hdtr *hdtr, int flags
)

int
connectx(
int socket, const sa_endpoints_t *endpoints, sae_associd_t associd, unsigned
int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len,
sae_connid_t *connid
)

int
disconnectx(
int socket, sae_associd_t associd, sae_connid_t connid
)



```

- structs:
```c
// the most common sockaddr type used:
struct sockaddr_storage {
  __uint8_t     ss_len;
  sa_family_t   ss_family;
  char        __ss_pad1[];
  __int64_t   __ss_align;
  char        __ss_pad2[];
}

/* Sockaddr endpoints */
typedef struct sa_endpoints {
  unsigned int sae_srcif;               // optional source interface
  const struct sockaddr *sae_srcaddr;   // optional src addr
  socklen_t sae_srcaddrlen;     // size of src addr
  const struct sockaddr *sae_dstaddr;   // dst addr
  socklen_t sae_dstaddrlen;     // size of dst addr
} sa_endpoints_t;

struct linger {
  int l_onoff;    // on/off flag
  int l_linger;   // linger time
}

// structure used by kernel for most addresses:
struct sockaddr {
  __uint8_t   sa_len;       // length
  sa_family_t sa_family;    // addr family
  char        sa_data[14];  // addr value (actually larger)
}
#define SOCK_MAXADDRLEN 255 /* longest possible address */

// struct used by kernel to pass protocol info in raw sockets
struct sockproto {
  __uint16_t sp_family;    // address family
  __uint16_t sp_protocol;  // protocol
}
```
