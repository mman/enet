/** 
 @file  unix.c
 @brief ENet Unix system specific functions
*/
#ifndef _WIN32

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define ENET_BUILDING_LIB 1
#include "enet/enet.h"

#ifdef __APPLE__
#ifdef HAS_POLL
#undef HAS_POLL
#endif
#ifndef HAS_FCNTL
#define HAS_FCNTL 1
#endif
#ifndef HAS_INET_PTON
#define HAS_INET_PTON 1
#endif
#ifndef HAS_INET_NTOP
#define HAS_INET_NTOP 1
#endif
#ifndef HAS_MSGHDR_FLAGS
#define HAS_MSGHDR_FLAGS 1
#endif
#ifndef HAS_SOCKLEN_T
#define HAS_SOCKLEN_T 1
#endif
#ifndef HAS_GETADDRINFO
#define HAS_GETADDRINFO 1
#endif
#ifndef HAS_GETNAMEINFO
#define HAS_GETNAMEINFO 1
#endif
#define __APPLE_USE_RFC_3542 1
#endif

#ifdef HAS_FCNTL
#include <fcntl.h>
#endif

#ifdef HAS_POLL
#include <poll.h>
#endif

#if !defined(HAS_SOCKLEN_T) && !defined(__socklen_t_defined)
typedef int socklen_t;
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static enet_uint32 timeBase = 0;

int
enet_initialize (void)
{
    return 0;
}

void
enet_deinitialize (void)
{
}

enet_uint32
enet_host_random_seed (void)
{
    return (enet_uint32) time (NULL);
}

enet_uint32
enet_time_get (void)
{
    struct timeval timeVal;

    gettimeofday (& timeVal, NULL);

    long long temporary = timeVal.tv_sec * (long long)1000 + timeVal.tv_usec / (long long)1000;

    return (enet_uint32)(temporary - timeBase);
}

void
enet_time_set (enet_uint32 newTimeBase)
{
    struct timeval timeVal;

    gettimeofday (& timeVal, NULL);

    long long temporary = timeVal.tv_sec * (long long)1000 + timeVal.tv_usec / (long long)1000;

    timeBase = (enet_uint32)(temporary - newTimeBase);
}

int
enet_address_set_host_ip (ENetAddress * address, const char * name)
{
#ifdef HAS_INET_PTON
    if (! inet_pton (AF_INET, name, & address -> host))
#else
    if (! inet_aton (name, (struct in_addr *) & address -> host))
#endif
        return -1;

    return 0;
}

int
enet_address_set_host (ENetAddress * address, const char * name)
{
#ifdef HAS_GETADDRINFO
    struct addrinfo hints, * resultList = NULL, * result = NULL;

    memset (& hints, 0, sizeof (hints));
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo (name, NULL, & hints, & resultList) != 0)
      return -1;

    for (result = resultList; result != NULL; result = result -> ai_next)
    {
        if (result -> ai_addr != NULL && result -> ai_addrlen >= sizeof (struct sockaddr_in))
        {
            if (result -> ai_family == AF_INET)
            {
                struct sockaddr_in * sin = (struct sockaddr_in *) result -> ai_addr;

                ((uint32_t *) & address -> host.s6_addr)[0] = 0;
                ((uint32_t *) & address -> host.s6_addr)[1] = 0;
                ((uint32_t *) & address -> host.s6_addr)[2] = htonl(0xffff);
                ((uint32_t *) & address -> host.s6_addr)[3] = sin->sin_addr.s_addr;

                freeaddrinfo (resultList);

                return 0;
            }
            else if(result -> ai_family == AF_INET6)
            {
                struct sockaddr_in6 * sin = (struct sockaddr_in6 *) result -> ai_addr;

                address -> host = sin -> sin6_addr;

                freeaddrinfo (resultList);

                return 0;
            }
        }
    }

    if (resultList != NULL)
      freeaddrinfo (resultList);
#else
#warning "Really use gethostbyname() with IPv6? Not all platforms support it."
    struct hostent * hostEntry = NULL;
#ifdef HAS_GETHOSTBYNAME_R
    struct hostent hostData;
    char buffer [2048];
    int errnum;

#if defined(linux) || defined(__linux) || defined(__linux__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__DragonFly__) || defined(__GNU__)
    gethostbyname_r (name, & hostData, buffer, sizeof (buffer), & hostEntry, & errnum);
#else
    hostEntry = gethostbyname_r (name, & hostData, buffer, sizeof (buffer), & errnum);
#endif
#else
    hostEntry = gethostbyname (name);
#endif

    if (hostEntry != NULL && hostEntry -> h_addrtype == AF_INET6)
    {
        address -> host = *(struct in6_addr *) hostEntry -> h_addr_list [0];

        return 0;
    }
#endif

#ifdef HAS_INET_PTON
    if (! inet_pton (AF_INET6, name, & address -> host))
#else
#error "inet_pton() is needed for IPv6 support"
    if (! inet_aton (name, (struct in_addr *) & address -> host))
#endif
        return -1;

    return 0;
}

int
enet_address_get_host_ip (const ENetAddress * address, char * name, size_t nameLength)
{
#ifdef HAS_INET_NTOP
    if (inet_ntop (AF_INET6, & address -> host, name, (socklen_t)nameLength) == NULL)
#else
#error "inet_ntop() is needed for IPv6 support"
    char * addr = inet_ntoa (* (struct in_addr *) & address -> host);
    if (addr != NULL)
    {
        size_t addrLen = strlen(addr);
        if (addrLen >= nameLength)
          return -1;
        memcpy (name, addr, addrLen + 1);
    } 
    else
#endif
        return -1;
    return 0;
}

int
enet_address_get_host (const ENetAddress * address, char * name, size_t nameLength)
{

#ifdef HAS_GETNAMEINFO
    struct sockaddr_in6 sin;
    int err;

    memset (& sin, 0, sizeof (struct sockaddr_in));

    sin.sin6_family = AF_INET6;
    sin.sin6_port = ENET_HOST_TO_NET_16 (address -> port);
    sin.sin6_addr = address -> host;

    err = getnameinfo ((struct sockaddr *) & sin, sizeof (sin), name, (socklen_t)nameLength, NULL, 0, NI_NAMEREQD);
    if (! err)
    {
        if (name != NULL && nameLength > 0 && ! memchr (name, '\0', nameLength))
          return -1;
        return 0;
    }
    if (err != EAI_NONAME)
      return -1;
#else
#warning "Really use gethostbyaddr() with IPv6? Not all platforms support it."
    struct in6_addr in;
    struct hostent * hostEntry = NULL;
#ifdef HAS_GETHOSTBYADDR_R
    struct hostent hostData;
    char buffer [2048];
    int errnum;

    in = address -> host;

#if defined(linux) || defined(__linux) || defined(__linux__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__DragonFly__) || defined(__GNU__)
    gethostbyaddr_r ((char *) & in, sizeof (struct in_addr), AF_INET, & hostData, buffer, sizeof (buffer), & hostEntry, & errnum);
#else
    hostEntry = gethostbyaddr_r ((char *) & in, sizeof (struct in6_addr), AF_INET6, & hostData, buffer, sizeof (buffer), & errnum);
#endif
#else
    in = address -> host;

    hostEntry = gethostbyaddr ((char *) & in, sizeof (struct in6_addr), AF_INET6);
#endif

    if (hostEntry != NULL)
    {
       size_t hostLen = strlen (hostEntry -> h_name);
       if (hostLen >= nameLength)
         return -1;
       memcpy (name, hostEntry -> h_name, hostLen + 1);
       return 0;
    }
#endif

    return enet_address_get_host_ip (address, name, nameLength);
}

int
enet_socket_bind (ENetSocket socket, const ENetAddress * address)
{
    struct sockaddr_in6 sin;

    memset (& sin, 0, sizeof (struct sockaddr_in6));

    sin.sin6_family = AF_INET6;

    if (address != NULL)
    {
       sin.sin6_port = ENET_HOST_TO_NET_16 (address -> port);
       sin.sin6_addr = address -> host;
       sin.sin6_scope_id = address -> sin6_scope_id;
    }
    else
    {
       sin.sin6_port = 0;
       sin.sin6_addr = in6addr_any;
       sin.sin6_scope_id = 0;
    }

    return bind (socket,
                 (struct sockaddr *) & sin,
                 sizeof (struct sockaddr_in6)); 
}

int
enet_socket_get_address (ENetSocket socket, ENetAddress * address)
{
    struct sockaddr_in6 sin;
    socklen_t sinLength = sizeof (struct sockaddr_in6);

    if (getsockname (socket, (struct sockaddr *) & sin, & sinLength) == -1)
      return -1;

    address -> host = sin.sin6_addr;
    address -> port = ENET_NET_TO_HOST_16 (sin.sin6_port);
    address -> sin6_scope_id = sin.sin6_scope_id;

    return 0;
}

int 
enet_socket_listen (ENetSocket socket, int backlog)
{
    return listen (socket, backlog < 0 ? SOMAXCONN : backlog);
}

ENetSocket
enet_socket_create (ENetSocketType type)
{
    return socket (PF_INET6, type == ENET_SOCKET_TYPE_DATAGRAM ? SOCK_DGRAM : SOCK_STREAM, 0);
}

int
enet_socket_set_option (ENetSocket socket, ENetSocketOption option, int value)
{
    int result = -1;
    switch (option)
    {
        case ENET_SOCKOPT_NONBLOCK:
#ifdef HAS_FCNTL
            result = fcntl (socket, F_SETFL, (value ? O_NONBLOCK : 0) | (fcntl (socket, F_GETFL) & ~O_NONBLOCK));
#else
            result = ioctl (socket, FIONBIO, & value);
#endif
            break;

        case ENET_SOCKOPT_REUSEADDR:
            result = setsockopt (socket, SOL_SOCKET, SO_REUSEADDR, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_RCVBUF:
            result = setsockopt (socket, SOL_SOCKET, SO_RCVBUF, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_SNDBUF:
            result = setsockopt (socket, SOL_SOCKET, SO_SNDBUF, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_RCVTIMEO:
        {
            struct timeval timeVal;
            timeVal.tv_sec = value / 1000;
            timeVal.tv_usec = (value % 1000) * 1000;
            result = setsockopt (socket, SOL_SOCKET, SO_RCVTIMEO, (char *) & timeVal, sizeof (struct timeval));
            break;
        }

        case ENET_SOCKOPT_SNDTIMEO:
        {
            struct timeval timeVal;
            timeVal.tv_sec = value / 1000;
            timeVal.tv_usec = (value % 1000) * 1000;
            result = setsockopt (socket, SOL_SOCKET, SO_SNDTIMEO, (char *) & timeVal, sizeof (struct timeval));
            break;
        }

        case ENET_SOCKOPT_NODELAY:
            result = setsockopt (socket, IPPROTO_TCP, TCP_NODELAY, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_IPV6_V6ONLY:
            result = setsockopt (socket, IPPROTO_IPV6, IPV6_V6ONLY, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_IPV6_RECVPKTINFO:
            result = setsockopt (socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_QOS:
#ifdef SO_NET_SERVICE_TYPE
            // iOS/macOS
            value = value ? NET_SERVICE_TYPE_VO : NET_SERVICE_TYPE_BE;
            result = setsockopt (socket, SOL_SOCKET, SO_NET_SERVICE_TYPE, (char *) & value, sizeof (int));
#else
#ifdef IP_TOS
            // UNIX - IPv4
            value = value ? 46 << 2 : 0; // DSCP: Expedited Forwarding
            result = setsockopt (socket, IPPROTO_IP, IP_TOS, (char *) & value, sizeof (int));
#endif
#ifdef IPV6_TCLASS
            // UNIX - IPv6
            value = value ? 46 << 2: 0; // DSCP: Expedited Forwarding
            result = setsockopt (socket, IPPROTO_IPV6, IPV6_TCLASS, (char *) & value, sizeof (int));
#endif
#ifdef SO_PRIORITY
            // Linux
            value = value ? 6 : 0; // Max priority without NET_CAP_ADMIN
            result = setsockopt (socket, SOL_SOCKET, SO_PRIORITY, (char *) & value, sizeof (int));
#endif
#endif /* SO_NET_SERVICE_TYPE */
            break;

        case ENET_SOCKOPT_TTL:
            result = setsockopt (socket, IPPROTO_IP, IP_TTL, (char *) & value, sizeof (int));
            break;

        default:
            break;
    }
    return result == -1 ? -1 : 0;
}

int
enet_socket_get_option (ENetSocket socket, ENetSocketOption option, int * value)
{
    int result = -1;
    socklen_t len;
    switch (option)
    {
        case ENET_SOCKOPT_ERROR:
            len = sizeof (int);
            result = getsockopt (socket, SOL_SOCKET, SO_ERROR, value, & len);
            break;

        case ENET_SOCKOPT_TTL:
            len = sizeof (int);
            result = getsockopt (socket, IPPROTO_IP, IP_TTL, (char *) value, & len);
            break;

        default:
            break;
    }
    return result == -1 ? -1 : 0;
}

int
enet_socket_connect (ENetSocket socket, const ENetAddress * address)
{
    struct sockaddr_in6 sin;
    int result;

    memset (& sin, 0, sizeof (struct sockaddr_in6));

    sin.sin6_family = AF_INET6;
    sin.sin6_port = ENET_HOST_TO_NET_16 (address -> port);
    sin.sin6_addr = address -> host;
    sin.sin6_scope_id = address -> sin6_scope_id;

    result = connect (socket, (struct sockaddr *) & sin, sizeof (struct sockaddr_in6));
    if (result == -1 && errno == EINPROGRESS)
      return 0;

    return result;
}

ENetSocket
enet_socket_accept (ENetSocket socket, ENetAddress * address)
{
    int result;
    struct sockaddr_in6 sin;
    socklen_t sinLength = sizeof (struct sockaddr_in6);

    result = accept (socket, 
                     address != NULL ? (struct sockaddr *) & sin : NULL, 
                     address != NULL ? & sinLength : NULL);
    
    if (result == -1)
      return ENET_SOCKET_NULL;

    if (address != NULL)
    {
        address -> host = sin.sin6_addr;
        address -> port = ENET_NET_TO_HOST_16 (sin.sin6_port);
        address -> sin6_scope_id = sin.sin6_scope_id;
    }

    return result;
} 
    
int
enet_socket_shutdown (ENetSocket socket, ENetSocketShutdown how)
{
    return shutdown (socket, (int) how);
}

void
enet_socket_destroy (ENetSocket socket)
{
    if (socket != -1)
      close (socket);
}

int
enet_socket_send (void * enetPeer, ENetSocket socket,
                  const ENetAddress * destinationAddress,
                  const ENetBuffer * buffers,
                  size_t bufferCount,
                  const ENetAddress * sourceAddress)
{
    struct msghdr msgHdr;
    struct sockaddr_in6 sin;
    int sentLength;
    struct cmsghdr *control_msg;
    char control_buf[256];
    struct in6_pktinfo *packet;

    memset (& msgHdr, 0, sizeof (struct msghdr));

    if (destinationAddress != NULL)
    {
        memset (& sin, 0, sizeof (struct sockaddr_in6));

        sin.sin6_family = AF_INET6;
        sin.sin6_port = ENET_HOST_TO_NET_16 (destinationAddress -> port);
        sin.sin6_addr = destinationAddress -> host;
        sin.sin6_scope_id = destinationAddress -> sin6_scope_id;

        msgHdr.msg_name = & sin;
        msgHdr.msg_namelen = sizeof (struct sockaddr_in6);
    }

    if (sourceAddress != NULL && !in6_equal(sourceAddress->host, in6addr_any))
    {
        msgHdr.msg_control = control_buf;
        msgHdr.msg_controllen = sizeof(control_buf);

        control_msg = CMSG_FIRSTHDR(&msgHdr);
        control_msg->cmsg_level = IPPROTO_IPV6;
        control_msg->cmsg_type = IPV6_PKTINFO;
        control_msg->cmsg_len = CMSG_LEN(sizeof(*packet));

        packet = (struct in6_pktinfo *) CMSG_DATA(control_msg);
        memset(packet, 0, sizeof(*packet));
        packet->ipi6_addr = sourceAddress->host;
        packet->ipi6_ifindex = sourceAddress->sin6_scope_id;
        msgHdr.msg_controllen = control_msg->cmsg_len;
    }

    msgHdr.msg_iov = (struct iovec *) buffers;
    msgHdr.msg_iovlen = (int)bufferCount;

    sentLength = (int)sendmsg (socket, & msgHdr, MSG_NOSIGNAL);
    
    if (sentLength == -1)
    {
       if (errno == EWOULDBLOCK)
         return 0;

       return -1;
    }

    return sentLength;
}

int
enet_socket_receive (void * host,
                     ENetSocket socket,
                     ENetAddress * sourceAddress,
                     ENetBuffer * buffers,
                     size_t bufferCount,
                     ENetAddress * destinationAddress)
{
    struct msghdr msgHdr;
    struct sockaddr_in6 sin;
    int recvLength;

    struct cmsghdr *cmptr;
    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(struct in6_addr)) +
                     CMSG_SPACE(sizeof(struct in6_pktinfo))] ;
    } control_un;

    memset (& msgHdr, 0, sizeof (struct msghdr));

    msgHdr.msg_control = control_un.control;
    msgHdr.msg_controllen = sizeof(control_un.control);
    msgHdr.msg_flags = 0;

    if (sourceAddress != NULL)
    {
        msgHdr.msg_name = & sin;
        msgHdr.msg_namelen = sizeof (struct sockaddr_in6);
    }

    msgHdr.msg_iov = (struct iovec *) buffers;
    msgHdr.msg_iovlen = (int)bufferCount;

    recvLength = (int)recvmsg (socket, & msgHdr, MSG_NOSIGNAL);

    if (recvLength == -1)
    {
        switch (errno)
        {
            case EWOULDBLOCK:
                return 0;
            case EINTR:
            case EMSGSIZE:
                return -2;
            default:
                return -1;
        }
    }

#ifdef HAS_MSGHDR_FLAGS
    if (msgHdr.msg_flags & MSG_TRUNC)
      return -2;
#endif

    if (sourceAddress != NULL)
    {
        sourceAddress -> host = sin.sin6_addr;
        sourceAddress -> port = ENET_NET_TO_HOST_16 (sin.sin6_port);
        sourceAddress -> sin6_scope_id = sin.sin6_scope_id;
    }

    if (destinationAddress != NULL)
    {
        for (cmptr = CMSG_FIRSTHDR(&msgHdr); cmptr != NULL; cmptr = CMSG_NXTHDR(&msgHdr, cmptr)) {
            if (cmptr->cmsg_level == IPPROTO_IPV6 && cmptr->cmsg_type == IPV6_PKTINFO) {
                struct in6_pktinfo *p = (struct in6_pktinfo *) CMSG_DATA(cmptr);
                destinationAddress->host = p->ipi6_addr;
                destinationAddress->sin6_scope_id = p->ipi6_ifindex;
                continue;
            }
        }
    }

    return recvLength;
}

int
enet_socketset_select (ENetSocket maxSocket, ENetSocketSet * readSet, ENetSocketSet * writeSet, enet_uint32 timeout)
{
    struct timeval timeVal;

    timeVal.tv_sec = timeout / 1000;
    timeVal.tv_usec = (timeout % 1000) * 1000;

    return select (maxSocket + 1, readSet, writeSet, NULL, & timeVal);
}

int
enet_socket_wait (ENetSocket socket, enet_uint32 * condition, enet_uint32 timeout)
{
#ifdef HAS_POLL
    struct pollfd pollSocket;
    int pollCount;
    
    pollSocket.fd = socket;
    pollSocket.events = 0;

    if (* condition & ENET_SOCKET_WAIT_SEND)
      pollSocket.events |= POLLOUT;

    if (* condition & ENET_SOCKET_WAIT_RECEIVE)
      pollSocket.events |= POLLIN;

    pollCount = poll (& pollSocket, 1, timeout);

    if (pollCount < 0)
    {
        if (errno == EINTR && * condition & ENET_SOCKET_WAIT_INTERRUPT)
        {
            * condition = ENET_SOCKET_WAIT_INTERRUPT;

            return 0;
        }

        return -1;
    }

    * condition = ENET_SOCKET_WAIT_NONE;

    if (pollCount == 0)
      return 0;

    if (pollSocket.revents & POLLOUT)
      * condition |= ENET_SOCKET_WAIT_SEND;
    
    if (pollSocket.revents & POLLIN)
      * condition |= ENET_SOCKET_WAIT_RECEIVE;

    return 0;
#else
    fd_set readSet, writeSet;
    struct timeval timeVal;
    int selectCount;

    timeVal.tv_sec = timeout / 1000;
    timeVal.tv_usec = (timeout % 1000) * 1000;

    FD_ZERO (& readSet);
    FD_ZERO (& writeSet);

    if (* condition & ENET_SOCKET_WAIT_SEND)
      FD_SET (socket, & writeSet);

    if (* condition & ENET_SOCKET_WAIT_RECEIVE)
      FD_SET (socket, & readSet);

    selectCount = select (socket + 1, & readSet, & writeSet, NULL, & timeVal);

    if (selectCount < 0)
    {
        if (errno == EINTR && * condition & ENET_SOCKET_WAIT_INTERRUPT)
        {
            * condition = ENET_SOCKET_WAIT_INTERRUPT;

            return 0;
        }
      
        return -1;
    }

    * condition = ENET_SOCKET_WAIT_NONE;

    if (selectCount == 0)
      return 0;

    if (FD_ISSET (socket, & writeSet))
      * condition |= ENET_SOCKET_WAIT_SEND;

    if (FD_ISSET (socket, & readSet))
      * condition |= ENET_SOCKET_WAIT_RECEIVE;

    return 0;
#endif
}

#endif

