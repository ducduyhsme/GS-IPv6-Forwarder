#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#pragma comment(lib, "ws2_32")
#include <WinSock2.h>
#include <Mswsock.h>
#include <Ws2ipdef.h>
#include <WS2tcpip.h>

#pragma comment(lib, "iphlpapi")
#include <Iphlpapi.h>

#pragma comment(lib, "miniupnpc.lib")
#define MINIUPNP_STATICLIB

#define SERVICE_NAME L"GSv6FwdSvc"
#define GAA_INITIAL_SIZE 8192

LPFN_WSARECVMSG WSARecvMsg;

#else // Linux/Unix

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netdb.h>

// Linux type definitions for Windows compatibility
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSE_SOCKET close
#define closesocket close

typedef struct sockaddr* PSOCKADDR;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr_in* PSOCKADDR_IN;
typedef struct sockaddr_in6 SOCKADDR_IN6;
typedef struct sockaddr_in6* PSOCKADDR_IN6;
typedef struct sockaddr_storage SOCKADDR_STORAGE;
typedef struct sockaddr_storage* PSOCKADDR_STORAGE;
typedef struct in_addr IN_ADDR;
typedef struct in_addr* PIN_ADDR;
typedef struct in6_addr IN6_ADDR;
typedef unsigned long DWORD;
typedef void* PVOID;
typedef unsigned long ULONG;

#define SD_SEND SHUT_WR
#define SD_BOTH SHUT_RDWR
#define ERROR_OUTOFMEMORY ENOMEM

#define RtlZeroMemory(dest, len) memset((dest), 0, (len))
#define RtlEqualMemory(a, b, len) (memcmp((a), (b), (len)) == 0)

// recvmsg/sendmsg structures for Linux (equivalent to Windows WSAMSG)
struct linux_iovec {
    void* buf;
    size_t len;
};

#endif // _WIN32

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#include "../version.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

bool PCPMapPort(PSOCKADDR_STORAGE localAddr, int localAddrLen, PSOCKADDR_STORAGE pcpAddr, int pcpAddrLen, int proto, int port, bool enable, bool indefinite);

static const unsigned short UDP_PORTS[] = {
    47998, 47999, 48000, 48002, 48010
};

static const unsigned short TCP_PORTS[] = {
    47984, 47989, 48010
};

typedef struct _SOCKET_TUPLE {
    SOCKET s1;
    SOCKET s2;
} SOCKET_TUPLE, *PSOCKET_TUPLE;

typedef struct _LISTENER_TUPLE {
    SOCKET listener;
    unsigned short port;
} LISTENER_TUPLE, *PLISTENER_TUPLE;

typedef struct _UDP_TUPLE {
    SOCKET ipv6Socket;
    SOCKET ipv4Socket;
    unsigned short port;
} UDP_TUPLE, *PUDP_TUPLE;

int
ForwardSocketData(SOCKET from, SOCKET to)
{
    char buffer[4096];
    int len;

    len = recv(from, buffer, sizeof(buffer), 0);
    if (len <= 0) {
        return len;
    }

    if (send(to, buffer, len, 0) != len) {
        return SOCKET_ERROR;
    }

    return len;
}

#ifdef _WIN32
DWORD
WINAPI
TcpRelayThreadProc(LPVOID Context)
#else
void*
TcpRelayThreadProc(void* Context)
#endif
{
    PSOCKET_TUPLE tuple = (PSOCKET_TUPLE)Context;
    fd_set fds;
    int err;
    bool s1ReadShutdown = false;
    bool s2ReadShutdown = false;
#ifndef _WIN32
    int maxfd;
#endif

    for (;;) {
        FD_ZERO(&fds);

        if (!s1ReadShutdown) {
            FD_SET(tuple->s1, &fds);
        }
        if (!s2ReadShutdown) {
            FD_SET(tuple->s2, &fds);
        }
        if (s1ReadShutdown && s2ReadShutdown) {
            // Both sides gracefully closed
            break;
        }

#ifdef _WIN32
        err = select(0, &fds, NULL, NULL, NULL);
#else
        maxfd = (tuple->s1 > tuple->s2) ? tuple->s1 : tuple->s2;
        err = select(maxfd + 1, &fds, NULL, NULL, NULL);
#endif
        if (err <= 0) {
            break;
        }
        else if (FD_ISSET(tuple->s1, &fds)) {
            err = ForwardSocketData(tuple->s1, tuple->s2);
            if (err == 0) {
                // Graceful closure from s1. Propagate to s2.
                shutdown(tuple->s2, SD_SEND);
                s1ReadShutdown = true;
            }
            else if (err < 0) {
                // Forceful closure. Tear down the whole connection.
                break;
            }
        }
        else if (FD_ISSET(tuple->s2, &fds)) {
            err = ForwardSocketData(tuple->s2, tuple->s1);
            if (err == 0) {
                // Graceful closure from s2. Propagate to s1.
                shutdown(tuple->s1, SD_SEND);
                s2ReadShutdown = true;
            }
            else if (err < 0) {
                // Forceful closure. Tear down the whole connection.
                break;
            }
        }
    }

    closesocket(tuple->s1);
    closesocket(tuple->s2);
    free(tuple);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

#ifdef _WIN32
PIP_ADAPTER_ADDRESSES
AllocAndGetAdaptersAddresses(ULONG Family, ULONG Flags)
{
    PIP_ADAPTER_ADDRESSES addresses;
    ULONG length;
    ULONG error;

    addresses = NULL;
    length = GAA_INITIAL_SIZE;
    do {
        free(addresses);
        addresses = (PIP_ADAPTER_ADDRESSES)malloc(length);
        if (addresses == NULL) {
            printf("malloc(%u) failed\n", length);
            return NULL;
        }

        error = GetAdaptersAddresses(Family, Flags, NULL, addresses, &length);
    } while (error == ERROR_BUFFER_OVERFLOW);

    if (error != ERROR_SUCCESS) {
        printf("GetAdaptersAddresses() failed: %d\n", error);
        free(addresses);
        return NULL;
    }

    return addresses;
}

void
FindLocalAddressBySocket(SOCKET s, PIN_ADDR targetAddress)
{
    PIP_ADAPTER_ADDRESSES addresses;
    PIP_ADAPTER_ADDRESSES currentAdapter;
    PIP_ADAPTER_UNICAST_ADDRESS currentAddress;
    SOCKADDR_IN6 localSockAddr;
    int localSockAddrLen;

    // If we fail to find an address, return the loopback address
    targetAddress->S_un.S_addr = htonl(INADDR_LOOPBACK);

    // Get local address of the accepted socket so we can find the interface
    localSockAddrLen = sizeof(localSockAddr);
    if (getsockname(s, (PSOCKADDR)&localSockAddr, &localSockAddrLen) == SOCKET_ERROR) {
        printf("getsockname() failed: %d\n", WSAGetLastError());
        return;
    }

    // Get a list of all interfaces and addresses on the system
    addresses = AllocAndGetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME);
    if (addresses == NULL) {
        return;
    }

    // First, find the interface that owns the incoming address
    currentAdapter = addresses;
    while (currentAdapter != NULL) {
        // Check if this interface has the IP address we want
        currentAddress = currentAdapter->FirstUnicastAddress;
        while (currentAddress != NULL) {
            if (currentAddress->Address.lpSockaddr->sa_family == AF_INET6) {
                PSOCKADDR_IN6 ifaceAddrV6 = (PSOCKADDR_IN6)currentAddress->Address.lpSockaddr;
                if (RtlEqualMemory(&localSockAddr.sin6_addr, &ifaceAddrV6->sin6_addr, sizeof(IN6_ADDR))) {
                    break;
                }
            }

            currentAddress = currentAddress->Next;
        }

        if (currentAddress != NULL) {
            // It does, bail out
            break;
        }

        currentAdapter = currentAdapter->Next;
    }

    // Check if we found the incoming interface
    if (currentAdapter == NULL) {
        // Hopefully the error is caused by transient interface reconfiguration
        printf("Unable to find incoming interface\n");
        goto Exit;
    }

    // Now find an IPv4 address on this interface
    currentAddress = currentAdapter->FirstUnicastAddress;
    while (currentAddress != NULL) {
        if (currentAddress->Address.lpSockaddr->sa_family == AF_INET) {
            PSOCKADDR_IN ifaceAddrV4 = (PSOCKADDR_IN)currentAddress->Address.lpSockaddr;
            *targetAddress = ifaceAddrV4->sin_addr;
            goto Exit;
        }

        currentAddress = currentAddress->Next;
    }

    // If we get here, there was no IPv4 address on this interface.
    // This is a valid situation, for example if the IPv6 interface
    // has no IPv4 connectivity. In this case, we can preserve most
    // functionality by forwarding via localhost. WoL won't work but
    // the basic stuff will.

Exit:
    free(addresses);
    return;
}
#else // Linux implementation

void
FindLocalAddressBySocket(SOCKET s, PIN_ADDR targetAddress)
{
    struct ifaddrs *ifaddr, *ifa;
    SOCKADDR_IN6 localSockAddr;
    socklen_t localSockAddrLen;
    char ifname[IF_NAMESIZE] = {0};
    int foundInterface = 0;

    // Default to loopback
    targetAddress->s_addr = htonl(INADDR_LOOPBACK);

    // Get local address of the accepted socket
    localSockAddrLen = sizeof(localSockAddr);
    if (getsockname(s, (struct sockaddr*)&localSockAddr, &localSockAddrLen) == -1) {
        printf("getsockname() failed: %d\n", errno);
        return;
    }

    if (getifaddrs(&ifaddr) == -1) {
        printf("getifaddrs() failed: %d\n", errno);
        return;
    }

    // First pass: find the interface with our IPv6 address
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET6) {
            PSOCKADDR_IN6 ifaceAddrV6 = (PSOCKADDR_IN6)ifa->ifa_addr;
            if (memcmp(&localSockAddr.sin6_addr, &ifaceAddrV6->sin6_addr, sizeof(struct in6_addr)) == 0) {
                strncpy(ifname, ifa->ifa_name, IF_NAMESIZE - 1);
                foundInterface = 1;
                break;
            }
        }
    }

    if (!foundInterface) {
        printf("Unable to find incoming interface\n");
        freeifaddrs(ifaddr);
        return;
    }

    // Second pass: find an IPv4 address on this interface
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, ifname) == 0) {
            PSOCKADDR_IN ifaceAddrV4 = (PSOCKADDR_IN)ifa->ifa_addr;
            *targetAddress = ifaceAddrV4->sin_addr;
            break;
        }
    }

    freeifaddrs(ifaddr);
}
#endif // _WIN32

#ifdef _WIN32
DWORD
WINAPI
TcpListenerThreadProc(LPVOID Context)
#else
void*
TcpListenerThreadProc(void* Context)
#endif
{
    PLISTENER_TUPLE tuple = (PLISTENER_TUPLE)Context;
    SOCKET acceptedSocket, targetSocket;
    SOCKADDR_IN targetAddress;
    PSOCKET_TUPLE relayTuple;
#ifdef _WIN32
    HANDLE thread;
#else
    pthread_t thread;
#endif

    printf("TCP relay running for port %d\n", tuple->port);

    for (;;) {
        acceptedSocket = accept(tuple->listener, NULL, 0);
        if (acceptedSocket == INVALID_SOCKET) {
#ifdef _WIN32
            printf("accept() failed: %d\n", WSAGetLastError());
#else
            printf("accept() failed: %d\n", errno);
#endif
            break;
        }

        targetSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (targetSocket == INVALID_SOCKET) {
#ifdef _WIN32
            printf("socket() failed: %d\n", WSAGetLastError());
#else
            printf("socket() failed: %d\n", errno);
#endif
            closesocket(acceptedSocket);
            continue;
        }

        RtlZeroMemory(&targetAddress, sizeof(targetAddress));
        targetAddress.sin_family = AF_INET;
        targetAddress.sin_port = htons(tuple->port);
        FindLocalAddressBySocket(acceptedSocket, &targetAddress.sin_addr);

        if (connect(targetSocket, (PSOCKADDR)&targetAddress, sizeof(targetAddress)) == SOCKET_ERROR) {
            // FIXME: This can race with reopening stdout and cause a crash in the CRT
            //printf("connect() failed: %d\n", ...);
            closesocket(acceptedSocket);
            closesocket(targetSocket);
            continue;
        }

        relayTuple = (PSOCKET_TUPLE)malloc(sizeof(*relayTuple));
        if (relayTuple == NULL) {
            closesocket(acceptedSocket);
            closesocket(targetSocket);
            break;
        }

        relayTuple->s1 = acceptedSocket;
        relayTuple->s2 = targetSocket;

#ifdef _WIN32
        thread = CreateThread(NULL, 0, TcpRelayThreadProc, relayTuple, 0, NULL);
        if (thread == NULL) {
            printf("CreateThread() failed: %d\n", GetLastError());
            closesocket(acceptedSocket);
            closesocket(targetSocket);
            free(relayTuple);
            break;
        }

        CloseHandle(thread);
#else
        if (pthread_create(&thread, NULL, TcpRelayThreadProc, relayTuple) != 0) {
            printf("pthread_create() failed: %d\n", errno);
            closesocket(acceptedSocket);
            closesocket(targetSocket);
            free(relayTuple);
            break;
        }
        pthread_detach(thread);
#endif
    }

    closesocket(tuple->listener);
    free(tuple);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int StartTcpRelay(unsigned short Port, SOCKET* Listener)
{
    SOCKET listeningSocket;
    SOCKADDR_IN6 addr6;
    PLISTENER_TUPLE tuple;
#ifdef _WIN32
    HANDLE thread;
    DWORD val;
#else
    pthread_t thread;
    int val;
#endif

    listeningSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listeningSocket == INVALID_SOCKET) {
#ifdef _WIN32
        printf("socket() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
#else
        printf("socket() failed: %d\n", errno);
        return errno;
#endif
    }

#ifdef _WIN32
    val = PROTECTION_LEVEL_UNRESTRICTED;
    if (setsockopt(listeningSocket, IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, (char*)&val, sizeof(val)) == SOCKET_ERROR) {
        printf("setsockopt(IPV6_PROTECTION_LEVEL) failed: %d\n", WSAGetLastError());
    }
#else
    // On Linux, we don't need IPV6_PROTECTION_LEVEL, but we might want to set IPV6_V6ONLY to 0
    val = 0;
    if (setsockopt(listeningSocket, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) == -1) {
        printf("setsockopt(IPV6_V6ONLY) failed: %d\n", errno);
    }
#endif

    RtlZeroMemory(&addr6, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(Port);
    if (bind(listeningSocket, (PSOCKADDR)&addr6, sizeof(addr6)) == SOCKET_ERROR) {
#ifdef _WIN32
        printf("bind() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
#else
        printf("bind() failed: %d\n", errno);
        return errno;
#endif
    }

    if (listen(listeningSocket, SOMAXCONN) == SOCKET_ERROR) {
#ifdef _WIN32
        printf("listen() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
#else
        printf("listen() failed: %d\n", errno);
        return errno;
#endif
    }

    tuple = (PLISTENER_TUPLE)malloc(sizeof(*tuple));
    if (tuple == NULL) {
        return ERROR_OUTOFMEMORY;
    }

    tuple->listener = *Listener = listeningSocket;
    tuple->port = Port;

#ifdef _WIN32
    thread = CreateThread(NULL, 0, TcpListenerThreadProc, tuple, 0, NULL);
    if (thread == NULL) {
        printf("CreateThread() failed: %d\n", GetLastError());
        return GetLastError();
    }

    CloseHandle(thread);
#else
    if (pthread_create(&thread, NULL, TcpListenerThreadProc, tuple) != 0) {
        printf("pthread_create() failed: %d\n", errno);
        return errno;
    }
    pthread_detach(thread);
#endif
    return 0;
}

#ifdef _WIN32
int
ForwardUdpPacketV4toV6(PUDP_TUPLE tuple,
                       WSABUF* sourceInfoControlBuffer,
                       PSOCKADDR_IN6 targetAddress)
{
    DWORD len;
    char buffer[4096];
    WSABUF buf;
    WSAMSG msg;

    buf.buf = buffer;
    buf.len = sizeof(buffer);

    msg.name = NULL;
    msg.namelen = 0;
    msg.lpBuffers = &buf;
    msg.dwBufferCount = 1;
    msg.Control.buf = NULL;
    msg.Control.len = 0;
    msg.dwFlags = 0;
    if (WSARecvMsg(tuple->ipv4Socket, &msg, &len, NULL, NULL) == SOCKET_ERROR) {
        printf("WSARecvMsg() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    msg.name = (PSOCKADDR)targetAddress;
    msg.namelen = sizeof(*targetAddress);
    msg.lpBuffers->len = len;
    msg.Control = *sourceInfoControlBuffer;
    msg.dwFlags = 0;
    if (WSASendMsg(tuple->ipv6Socket, &msg, 0, &len, NULL, NULL) == SOCKET_ERROR) {
        printf("WSASendMsg() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    return 0;
}

int
ForwardUdpPacketV6toV4(PUDP_TUPLE tuple,
                       PSOCKADDR_IN targetAddress,
                       /* Out */ WSABUF* destInfoControlBuffer,
                       /* Out */ PSOCKADDR_IN6 sourceAddress)
{
    DWORD len;
    char buffer[4096];
    WSABUF buf;
    WSAMSG msg;

    buf.buf = buffer;
    buf.len = sizeof(buffer);

    msg.name = (PSOCKADDR)sourceAddress;
    msg.namelen = sizeof(*sourceAddress);
    msg.lpBuffers = &buf;
    msg.dwBufferCount = 1;
    msg.Control = *destInfoControlBuffer;
    msg.dwFlags = 0;
    if (WSARecvMsg(tuple->ipv6Socket, &msg, &len, NULL, NULL) == SOCKET_ERROR) {
        printf("WSARecvMsg() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    // IPV6_PKTINFO must be populated
    assert(WSA_CMSG_FIRSTHDR(&msg)->cmsg_level == IPPROTO_IPV6);
    assert(WSA_CMSG_FIRSTHDR(&msg)->cmsg_type == IPV6_PKTINFO);

    // Copy the returned data length back
    destInfoControlBuffer->len = msg.Control.len;

    msg.name = (PSOCKADDR)targetAddress;
    msg.namelen = sizeof(*targetAddress);
    msg.lpBuffers->len = len;
    msg.Control.buf = NULL;
    msg.Control.len = 0;
    msg.dwFlags = 0;
    if (WSASendMsg(tuple->ipv4Socket, &msg, 0, &len, NULL, NULL) == SOCKET_ERROR) {
        printf("WSASendMsg() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    return 0;
}

DWORD
WINAPI
UdpRelayThreadProc(LPVOID Context)
{
    PUDP_TUPLE tuple = (PUDP_TUPLE)Context;
    fd_set fds;
    int err;
    SOCKADDR_IN6 lastRemote;
    SOCKADDR_IN localTarget;
    char lastSourceBuf[1024];
    WSABUF lastSource;

    printf("UDP relay running for port %d\n", tuple->port);

    RtlZeroMemory(&localTarget, sizeof(localTarget));
    localTarget.sin_family = AF_INET;
    localTarget.sin_port = htons(tuple->port);
    localTarget.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);

    RtlZeroMemory(&lastRemote, sizeof(lastRemote));
    RtlZeroMemory(&lastSource, sizeof(lastSource));

    for (;;) {
        FD_ZERO(&fds);

        FD_SET(tuple->ipv6Socket, &fds);
        FD_SET(tuple->ipv4Socket, &fds);

        err = select(0, &fds, NULL, NULL, NULL);
        if (err <= 0) {
            break;
        }
        else if (FD_ISSET(tuple->ipv6Socket, &fds)) {
            // Forwarding incoming IPv6 packets to the IPv4 port
            // and storing the source address as our current remote
            // target for sending IPv4 data back. Collect the address
            // we received the packet on to be able to send from the same
            // source when we relay.
            lastSource.buf = lastSourceBuf;
            lastSource.len = sizeof(lastSourceBuf);

            // Don't check for errors to prevent transient issues (like GFE not having started yet)
            // from bringing down the whole relay.
            ForwardUdpPacketV6toV4(tuple, &localTarget, &lastSource, &lastRemote);
        }
        else if (FD_ISSET(tuple->ipv4Socket, &fds)) {
            // Forwarding incoming IPv4 packets to the last known
            // address IPv6 address we've heard from. Pass the destination data
            // from the last v6 packet we received to use as the source address.

            // Don't check for errors to prevent transient issues (like GFE not having started yet)
            // from bringing down the whole relay.
            ForwardUdpPacketV4toV6(tuple, &lastSource, &lastRemote);
        }
    }

    closesocket(tuple->ipv6Socket);
    closesocket(tuple->ipv4Socket);
    free(tuple);
    return 0;
}

int StartUdpRelay(unsigned short Port, SOCKET* Ipv4Socket, SOCKET* Ipv6Socket)
{
    SOCKET ipv6Socket;
    SOCKET ipv4Socket;
    SOCKADDR_IN6 addr6;
    SOCKADDR_IN addr;
    PUDP_TUPLE tuple;
    HANDLE thread;
    GUID wsaRecvMsgGuid = WSAID_WSARECVMSG;
    DWORD bytesReturned;
    DWORD val;

    ipv6Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (ipv6Socket == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    if (WSAIoctl(ipv6Socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &wsaRecvMsgGuid, sizeof(wsaRecvMsgGuid),
                 &WSARecvMsg, sizeof(WSARecvMsg), &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
        printf("WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSARecvMsg) failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    // IPV6_PKTINFO is required to ensure that the destination IPv6 address matches the source that
    // we send our reply from. If we don't do this, traffic destined to addresses that aren't the default
    // outgoing NIC/address will get dropped by the remote party.
    val = TRUE;
    if (setsockopt(ipv6Socket, IPPROTO_IPV6, IPV6_PKTINFO, (char*)&val, sizeof(val)) == SOCKET_ERROR) {
        printf("setsockopt(IPV6_PKTINFO) failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    val = PROTECTION_LEVEL_UNRESTRICTED;
    if (setsockopt(ipv6Socket, IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, (char*)&val, sizeof(val)) == SOCKET_ERROR) {
        printf("setsockopt(IPV6_PROTECTION_LEVEL) failed: %d\n", WSAGetLastError());
    }

    RtlZeroMemory(&addr6, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(Port);
    if (bind(ipv6Socket, (PSOCKADDR)&addr6, sizeof(addr6)) == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    ipv4Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ipv4Socket == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    RtlZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
    if (bind(ipv4Socket, (PSOCKADDR)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    tuple = (PUDP_TUPLE)malloc(sizeof(*tuple));
    if (tuple == NULL) {
        return ERROR_OUTOFMEMORY;
    }

    tuple->ipv4Socket = *Ipv4Socket = ipv4Socket;
    tuple->ipv6Socket = *Ipv6Socket = ipv6Socket;
    tuple->port = Port;

    thread = CreateThread(NULL, 0, UdpRelayThreadProc, tuple, 0, NULL);
    if (thread == NULL) {
        printf("CreateThread() failed: %d\n", GetLastError());
        return GetLastError();
    }

    CloseHandle(thread);

    return 0;
}

#else // Linux UDP relay implementation

// Linux control message buffer structure
typedef struct {
    char* buf;
    size_t len;
} LinuxControlBuffer;

int
ForwardUdpPacketV4toV6(PUDP_TUPLE tuple,
                       LinuxControlBuffer* sourceInfoControlBuffer,
                       PSOCKADDR_IN6 targetAddress)
{
    char buffer[4096];
    ssize_t len;
    struct iovec iov;
    struct msghdr msg;

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    len = recvmsg(tuple->ipv4Socket, &msg, 0);
    if (len < 0) {
        printf("recvmsg() failed: %d\n", errno);
        return errno;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = targetAddress;
    msg.msg_namelen = sizeof(*targetAddress);
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = sourceInfoControlBuffer->buf;
    msg.msg_controllen = sourceInfoControlBuffer->len;

    if (sendmsg(tuple->ipv6Socket, &msg, 0) < 0) {
        printf("sendmsg() failed: %d\n", errno);
        return errno;
    }

    return 0;
}

int
ForwardUdpPacketV6toV4(PUDP_TUPLE tuple,
                       PSOCKADDR_IN targetAddress,
                       /* Out */ LinuxControlBuffer* destInfoControlBuffer,
                       /* Out */ PSOCKADDR_IN6 sourceAddress)
{
    char buffer[4096];
    ssize_t len;
    struct iovec iov;
    struct msghdr msg;

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = sourceAddress;
    msg.msg_namelen = sizeof(*sourceAddress);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = destInfoControlBuffer->buf;
    msg.msg_controllen = destInfoControlBuffer->len;

    len = recvmsg(tuple->ipv6Socket, &msg, 0);
    if (len < 0) {
        printf("recvmsg() failed: %d\n", errno);
        return errno;
    }

    // Verify IPV6_PKTINFO is populated
    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
        destInfoControlBuffer->len = msg.msg_controllen;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = targetAddress;
    msg.msg_namelen = sizeof(*targetAddress);
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(tuple->ipv4Socket, &msg, 0) < 0) {
        printf("sendmsg() failed: %d\n", errno);
        return errno;
    }

    return 0;
}

void*
UdpRelayThreadProc(void* Context)
{
    PUDP_TUPLE tuple = (PUDP_TUPLE)Context;
    fd_set fds;
    int err;
    SOCKADDR_IN6 lastRemote;
    SOCKADDR_IN localTarget;
    char lastSourceBuf[1024];
    LinuxControlBuffer lastSource;
    int maxfd;

    printf("UDP relay running for port %d\n", tuple->port);

    RtlZeroMemory(&localTarget, sizeof(localTarget));
    localTarget.sin_family = AF_INET;
    localTarget.sin_port = htons(tuple->port);
    localTarget.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    RtlZeroMemory(&lastRemote, sizeof(lastRemote));
    RtlZeroMemory(&lastSource, sizeof(lastSource));

    maxfd = (tuple->ipv6Socket > tuple->ipv4Socket) ? tuple->ipv6Socket : tuple->ipv4Socket;

    for (;;) {
        FD_ZERO(&fds);

        FD_SET(tuple->ipv6Socket, &fds);
        FD_SET(tuple->ipv4Socket, &fds);

        err = select(maxfd + 1, &fds, NULL, NULL, NULL);
        if (err <= 0) {
            break;
        }
        else if (FD_ISSET(tuple->ipv6Socket, &fds)) {
            // Forwarding incoming IPv6 packets to the IPv4 port
            lastSource.buf = lastSourceBuf;
            lastSource.len = sizeof(lastSourceBuf);

            ForwardUdpPacketV6toV4(tuple, &localTarget, &lastSource, &lastRemote);
        }
        else if (FD_ISSET(tuple->ipv4Socket, &fds)) {
            // Forwarding incoming IPv4 packets to the last known IPv6 address
            ForwardUdpPacketV4toV6(tuple, &lastSource, &lastRemote);
        }
    }

    close(tuple->ipv6Socket);
    close(tuple->ipv4Socket);
    free(tuple);
    return NULL;
}

int StartUdpRelay(unsigned short Port, SOCKET* Ipv4Socket, SOCKET* Ipv6Socket)
{
    SOCKET ipv6Socket;
    SOCKET ipv4Socket;
    SOCKADDR_IN6 addr6;
    SOCKADDR_IN addr;
    PUDP_TUPLE tuple;
    pthread_t thread;
    int val;

    ipv6Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (ipv6Socket == INVALID_SOCKET) {
        printf("socket() failed: %d\n", errno);
        return errno;
    }

    // IPV6_PKTINFO is required to ensure that the destination IPv6 address matches the source
    val = 1;
    if (setsockopt(ipv6Socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val)) == -1) {
        printf("setsockopt(IPV6_RECVPKTINFO) failed: %d\n", errno);
        return errno;
    }

    // Allow both IPv4 and IPv6 on the same socket (optional)
    val = 1;
    if (setsockopt(ipv6Socket, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) == -1) {
        printf("setsockopt(IPV6_V6ONLY) failed: %d\n", errno);
    }

    RtlZeroMemory(&addr6, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(Port);
    if (bind(ipv6Socket, (struct sockaddr*)&addr6, sizeof(addr6)) == -1) {
        printf("bind() failed: %d\n", errno);
        return errno;
    }

    ipv4Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ipv4Socket == INVALID_SOCKET) {
        printf("socket() failed: %d\n", errno);
        return errno;
    }

    RtlZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ipv4Socket, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        printf("bind() failed: %d\n", errno);
        return errno;
    }

    tuple = (PUDP_TUPLE)malloc(sizeof(*tuple));
    if (tuple == NULL) {
        return ERROR_OUTOFMEMORY;
    }

    tuple->ipv4Socket = *Ipv4Socket = ipv4Socket;
    tuple->ipv6Socket = *Ipv6Socket = ipv6Socket;
    tuple->port = Port;

    if (pthread_create(&thread, NULL, UdpRelayThreadProc, tuple) != 0) {
        printf("pthread_create() failed: %d\n", errno);
        return errno;
    }
    pthread_detach(thread);

    return 0;
}

#endif // _WIN32

#ifdef _WIN32
void NETIOAPI_API_ IpInterfaceChangeNotificationCallback(PVOID context, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE)
{
    SetEvent((HANDLE)context);
}
#endif

void UPnPCreatePinholeForPort(struct UPNPUrls* urls, struct IGDdatas* data, int proto, const char* myAddr, int port)
{
    char uniqueId[8];
    char protoStr[3];
    char portStr[6];

    snprintf(portStr, sizeof(portStr), "%d", port);
    snprintf(protoStr, sizeof(protoStr), "%d", proto);

    printf("Creating UPnP IPv6 pinhole for %s %s -> %s...", protoStr, portStr, myAddr);

    // Lease time is in seconds - 7200 = 2 hours
    int err = UPNP_AddPinhole(urls->controlURL_6FC, data->IPv6FC.servicetype, "", "0", myAddr, portStr, protoStr, "7200", uniqueId);
    if (err == UPNPCOMMAND_SUCCESS) {
        printf("OK\n");
    }
    else {
        printf("ERROR %d (%s)\n", err, strupnperror(err));
    }
}

#ifdef _WIN32
void UPnPCreatePinholesForInterface(struct UPNPUrls* urls, struct IGDdatas* data, const char* tmpAddr)
{
    PIP_ADAPTER_ADDRESSES addresses;
    PIP_ADAPTER_ADDRESSES currentAdapter;
    PIP_ADAPTER_UNICAST_ADDRESS currentAddress;
    in6_addr targetAddress;

    inet_pton(AF_INET6, tmpAddr, &targetAddress);

    // Get a list of all interfaces with IPv6 addresses on the system
    addresses = AllocAndGetAdaptersAddresses(AF_INET6,
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME);
    if (addresses == NULL) {
        return;
    }

    currentAdapter = addresses;
    currentAddress = nullptr;
    while (currentAdapter != nullptr) {
        // First, search for the adapter
        currentAddress = currentAdapter->FirstUnicastAddress;
        while (currentAddress != nullptr) {
            assert(currentAddress->Address.lpSockaddr->sa_family == AF_INET6);

            PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)currentAddress->Address.lpSockaddr;

            if (RtlEqualMemory(&currentAddrV6->sin6_addr, &targetAddress, sizeof(targetAddress))) {
                // Found interface with matching address
                break;
            }

            currentAddress = currentAddress->Next;
        }

        if (currentAddress != nullptr) {
            // Get out of the loop if we found the matching address
            break;
        }

        currentAdapter = currentAdapter->Next;
    }

    if (currentAdapter == nullptr) {
        printf("No adapter found with IPv6 address: %s\n", tmpAddr);
        goto Exit;
    }

    // Now currentAdapter is the adapter we reached the IGD with. Create pinholes for all
    // public IPv6 addresses on this interface using this IGD.
    currentAddress = currentAdapter->FirstUnicastAddress;
    while (currentAddress != nullptr) {
        assert(currentAddress->Address.lpSockaddr->sa_family == AF_INET6);

        PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)currentAddress->Address.lpSockaddr;

        // Exclude link-local and privacy addresses
        if (currentAddrV6->sin6_scope_id == 0 && currentAddress->SuffixOrigin != IpSuffixOriginRandom) {
            char currentAddrStr[128] = {};

            inet_ntop(AF_INET6, &currentAddrV6->sin6_addr, currentAddrStr, sizeof(currentAddrStr));

            for (int i = 0; i < ARRAYSIZE(TCP_PORTS); i++) {
                UPnPCreatePinholeForPort(urls, data, IPPROTO_TCP, currentAddrStr, TCP_PORTS[i]);
            }
            for (int i = 0; i < ARRAYSIZE(UDP_PORTS); i++) {
                UPnPCreatePinholeForPort(urls, data, IPPROTO_UDP, currentAddrStr, UDP_PORTS[i]);
            }
        }

        currentAddress = currentAddress->Next;
    }

Exit:
    free(addresses);
    return;
}
#else // Linux implementation
void UPnPCreatePinholesForInterface(struct UPNPUrls* urls, struct IGDdatas* data, const char* tmpAddr)
{
    struct ifaddrs *ifaddr, *ifa;
    struct in6_addr targetAddress;
    char ifname[IF_NAMESIZE] = {0};
    int foundInterface = 0;

    inet_pton(AF_INET6, tmpAddr, &targetAddress);

    if (getifaddrs(&ifaddr) == -1) {
        printf("getifaddrs() failed: %d\n", errno);
        return;
    }

    // First pass: find the interface with the target address
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)ifa->ifa_addr;
        if (memcmp(&currentAddrV6->sin6_addr, &targetAddress, sizeof(targetAddress)) == 0) {
            strncpy(ifname, ifa->ifa_name, IF_NAMESIZE - 1);
            foundInterface = 1;
            break;
        }
    }

    if (!foundInterface) {
        printf("No adapter found with IPv6 address: %s\n", tmpAddr);
        freeifaddrs(ifaddr);
        return;
    }

    // Second pass: create pinholes for all public IPv6 addresses on this interface
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET6)
            continue;
        if (strcmp(ifa->ifa_name, ifname) != 0)
            continue;

        PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)ifa->ifa_addr;

        // Exclude link-local addresses (scope_id != 0 or starts with fe80)
        if (currentAddrV6->sin6_scope_id == 0 && 
            !IN6_IS_ADDR_LINKLOCAL(&currentAddrV6->sin6_addr)) {
            char currentAddrStr[128] = {};
            inet_ntop(AF_INET6, &currentAddrV6->sin6_addr, currentAddrStr, sizeof(currentAddrStr));

            for (size_t i = 0; i < ARRAYSIZE(TCP_PORTS); i++) {
                UPnPCreatePinholeForPort(urls, data, IPPROTO_TCP, currentAddrStr, TCP_PORTS[i]);
            }
            for (size_t i = 0; i < ARRAYSIZE(UDP_PORTS); i++) {
                UPnPCreatePinholeForPort(urls, data, IPPROTO_UDP, currentAddrStr, UDP_PORTS[i]);
            }
        }
    }

    freeifaddrs(ifaddr);
}
#endif

void UpdateUpnpPinholes()
{
    int upnpErr;
    struct UPNPUrls urls;
    struct IGDdatas data;
    char localAddress[128];
    (void)localAddress; // Silence unused variable warning in some code paths

    struct UPNPDev* ipv6Devs = upnpDiscoverAll(5000, NULL, NULL, UPNP_LOCAL_PORT_ANY, 1, 2, &upnpErr);
    printf("UPnP IPv6 IGD discovery completed with error code: %d\n", upnpErr);

    int ret = UPNP_GetValidIGD(ipv6Devs, &urls, &data, localAddress, sizeof(localAddress));
    if (ret == 0) {
        printf("No UPnP device found!\n");
        freeUPNPDevlist(ipv6Devs);
        return;
    }
    else if (ret == 3) {
        printf("No UPnP IGD found!\n");
        FreeUPNPUrls(&urls);
        freeUPNPDevlist(ipv6Devs);
        return;
    }
    else if (ret == 1) {
        printf("Found a connected UPnP IGD\n");
    }
    else if (ret == 2) {
        printf("Found a disconnected UPnP IGD (!)\n");
    }
    else {
        printf("UPNP_GetValidIGD() failed: %d\n", ret);
        freeUPNPDevlist(ipv6Devs);
        return;
    }

    // Don't try IPv6FC without a control URL
    if (data.IPv6FC.controlurl[0] != 0) {
        int firewallEnabled, pinholeAllowed;
        
        // Check if this firewall supports IPv6 pinholes
        ret = UPNP_GetFirewallStatus(urls.controlURL_6FC, data.IPv6FC.servicetype, &firewallEnabled, &pinholeAllowed);
        if (ret == UPNPCOMMAND_SUCCESS) {
            printf("UPnP IPv6 firewall control available. Firewall is %s, pinhole is %s\n",
                firewallEnabled ? "enabled" : "disabled",
                pinholeAllowed ? "allowed" : "disallowed");

            if (pinholeAllowed) {
                // If the IGD supports IPv6 pinholes, create them for all IPv6 addresses on this interface
                UPnPCreatePinholesForInterface(&urls, &data, localAddress);
            }
        }
        else {
            printf("UPnP IPv6 firewall control is unavailable with error %d (%s)\n", ret, strupnperror(ret));
        }
    }
    else {
        printf("IPv6 firewall control not supported by UPnP IGD!\n");
    }

    FreeUPNPUrls(&urls);
    freeUPNPDevlist(ipv6Devs);
}

#ifdef _WIN32
void UpdatePcpPinholes()
{
    PIP_ADAPTER_ADDRESSES addresses;
    PIP_ADAPTER_ADDRESSES currentAdapter;
    PIP_ADAPTER_UNICAST_ADDRESS currentAddress;

    // Get all IPv6 interfaces
    addresses = AllocAndGetAdaptersAddresses(AF_INET6,
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME |
        GAA_FLAG_INCLUDE_GATEWAYS);
    if (addresses == NULL) {
        return;
    }

    currentAdapter = addresses;
    while (currentAdapter != NULL) {
        // Skip over interfaces with no gateway
        if (currentAdapter->FirstGatewayAddress == NULL) {
            currentAdapter = currentAdapter->Next;
            continue;
        }

        PSOCKADDR_IN6 gatewayAddrV6 = (PSOCKADDR_IN6)currentAdapter->FirstGatewayAddress->Address.lpSockaddr;

        char addressStr[128];
        inet_ntop(AF_INET6, &gatewayAddrV6->sin6_addr, addressStr, sizeof(addressStr));

        printf("Using PCP server: %s%%%d\n", addressStr, gatewayAddrV6->sin6_scope_id);

        // Create pinholes for all IPv6 GUAs
        currentAddress = currentAdapter->FirstUnicastAddress;
        while (currentAddress != NULL) {
            assert(currentAddress->Address.lpSockaddr->sa_family == AF_INET6);

            PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)currentAddress->Address.lpSockaddr;

            // Exclude link-local and privacy addresses
            if (currentAddrV6->sin6_scope_id == 0 && currentAddress->SuffixOrigin != IpSuffixOriginRandom) {
                inet_ntop(AF_INET6, &currentAddrV6->sin6_addr, addressStr, sizeof(addressStr));
                printf("Updating PCP mappings for address %s\n", addressStr);

                for (int i = 0; i < ARRAYSIZE(TCP_PORTS); i++) {
                    PCPMapPort(
                        (PSOCKADDR_STORAGE)currentAddrV6,
                        currentAddress->Address.iSockaddrLength,
                        (PSOCKADDR_STORAGE)currentAdapter->FirstGatewayAddress->Address.lpSockaddr,
                        currentAdapter->FirstGatewayAddress->Address.iSockaddrLength,
                        IPPROTO_TCP,
                        TCP_PORTS[i],
                        true,
                        false);
                }
                for (int i = 0; i < ARRAYSIZE(UDP_PORTS); i++) {
                    PCPMapPort(
                        (PSOCKADDR_STORAGE)currentAddrV6,
                        currentAddress->Address.iSockaddrLength,
                        (PSOCKADDR_STORAGE)currentAdapter->FirstGatewayAddress->Address.lpSockaddr,
                        currentAdapter->FirstGatewayAddress->Address.iSockaddrLength,
                        IPPROTO_UDP,
                        UDP_PORTS[i],
                        true,
                        false);
                }
            }

            currentAddress = currentAddress->Next;
        }

        currentAdapter = currentAdapter->Next;
    }

    free(addresses);
}

void ResetLogFile(bool standaloneExe)
{
    char timeString[MAX_PATH + 1] = {};
    SYSTEMTIME time;

    if (!standaloneExe) {
        char oldLogFilePath[MAX_PATH + 1];
        char currentLogFilePath[MAX_PATH + 1];

        ExpandEnvironmentStringsA("%ProgramData%\\MISS\\GSv6Fwd-old.log", oldLogFilePath, sizeof(oldLogFilePath));
        ExpandEnvironmentStringsA("%ProgramData%\\MISS\\GSv6Fwd-current.log", currentLogFilePath, sizeof(currentLogFilePath));

        // Close the existing stdout handle. This is important because otherwise
        // it may still be open as stdout when we try to MoveFileEx below.
        fclose(stdout);

        // Rotate the current to the old log file
        MoveFileExA(currentLogFilePath, oldLogFilePath, MOVEFILE_REPLACE_EXISTING);

        // Redirect stdout to this new file
        if (freopen(currentLogFilePath, "w", stdout) == NULL) {
            // If we couldn't create a log file, just redirect stdout to NUL.
            // We have to open _something_ or printf() will crash.
            freopen("NUL", "w", stdout);
        }
    }

    // Print a log header
    printf("IPv6 Forwarder for GameStream v" VER_VERSION_STR "\n");

    // Print the current time
    GetSystemTime(&time);
    GetTimeFormatA(LOCALE_SYSTEM_DEFAULT, 0, &time, "hh':'mm':'ss tt", timeString, ARRAYSIZE(timeString));
    printf("The current UTC time is: %s\n", timeString);
}

bool IsGameStreamEnabled()
{
    DWORD error;
    DWORD enabled;
    DWORD len;
    HKEY key;

    error = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\NVIDIA Corporation\\NvStream", 0, KEY_READ | KEY_WOW64_64KEY, &key);
    if (error != ERROR_SUCCESS) {
        printf("RegOpenKeyEx() failed: %d\n", error);
        return false;
    }

    len = sizeof(enabled);
    error = RegQueryValueExA(key, "EnableStreaming", nullptr, nullptr, (LPBYTE)&enabled, &len);
    RegCloseKey(key);
    if (error != ERROR_SUCCESS) {
        printf("RegQueryValueExA() failed: %d\n", error);
        return false;
    }

    return enabled != 0;
}

DWORD WINAPI GameStreamStateChangeThread(PVOID Context)
{
    HKEY key;
    DWORD err;

    do {
        // We're watching this key that way we can still detect GameStream turning on
        // if GFE wasn't even installed when our service started
        do {
            err = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\NVIDIA Corporation", 0, KEY_READ | KEY_WOW64_64KEY, &key);
            if (err != ERROR_SUCCESS) {
                // Wait 10 seconds and try again
                Sleep(10000);
            }
        } while (err != ERROR_SUCCESS);

        // Notify the main thread when the GameStream state changes
        bool lastGameStreamState = IsGameStreamEnabled();
        while ((err = RegNotifyChangeKeyValue(key, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, nullptr, false)) == ERROR_SUCCESS) {
            bool currentGameStreamState = IsGameStreamEnabled();
            if (lastGameStreamState != currentGameStreamState) {
                SetEvent((HANDLE)Context);
            }
            lastGameStreamState = currentGameStreamState;
        }

        // If the key is deleted (by DDU or similar), we will hit this code path and poll until it comes back.
        RegCloseKey(key);
    } while (err == ERROR_KEY_DELETED);

    return err;
}

void StartRelay(SOCKET* tcpSockets, SOCKET* udpSockets) {
    int err;

    for (int i = 0; i < ARRAYSIZE(TCP_PORTS); i++) {
        err = StartTcpRelay(TCP_PORTS[i], &tcpSockets[i]);
        if (err != 0) {
            printf("Failed to start relay on TCP %d: %d\n", TCP_PORTS[i], err);
            tcpSockets[i] = INVALID_SOCKET;
        }
    }

    for (int i = 0; i < ARRAYSIZE(UDP_PORTS); i++) {
        err = StartUdpRelay(UDP_PORTS[i], &udpSockets[i * 2], &udpSockets[i * 2 + 1]);
        if (err != 0) {
            printf("Failed to start relay on UDP %d: %d\n", UDP_PORTS[i], err);
            udpSockets[i * 2] = udpSockets[i * 2 + 1] = INVALID_SOCKET;
        }
    }
}

int Run(bool standaloneExe)
{
    int err;
    WSADATA data;

    ResetLogFile(standaloneExe);

    HANDLE ifaceChangeEvent = CreateEvent(nullptr, true, false, nullptr);
    HANDLE gameStreamStateChangeEvent = CreateEvent(nullptr, true, false, nullptr);

    err = WSAStartup(MAKEWORD(2, 0), &data);
    if (err == SOCKET_ERROR) {
        printf("WSAStartup() failed: %d\n", err);
        return err;
    }

    // Watch for IPv6 address and interface changes
    HANDLE ifaceChangeHandle;
    NotifyIpInterfaceChange(AF_INET6, IpInterfaceChangeNotificationCallback, ifaceChangeEvent, false, &ifaceChangeHandle);

    // Watch for GameStream state changes
    HANDLE stateChangeThread = CreateThread(NULL, 0, GameStreamStateChangeThread, gameStreamStateChangeEvent, 0, NULL);
    if (stateChangeThread == NULL) {
        printf("CreateThread() failed: %d\n", GetLastError());
        return GetLastError();
    }
    CloseHandle(stateChangeThread);

    // Ensure we get adequate CPU time even when the PC is heavily loaded
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    // Keep track of TCP and UDP sockets for the relays. UDP requires 2 sockets per port (1 for v4 and 1 for v6).
    SOCKET tcpSockets[ARRAYSIZE(TCP_PORTS)] = {};
    SOCKET udpSockets[ARRAYSIZE(UDP_PORTS) * 2] = {};

    // Start the relays if GameStream is on
    if (IsGameStreamEnabled()) {
        StartRelay(tcpSockets, udpSockets);
    }

    for (;;) {
        ResetEvent(ifaceChangeEvent);

        // Update pinholes if GameStream is enabled
        if (IsGameStreamEnabled()) {
            printf("GameStream is enabled\n");

            UpdatePcpPinholes();
            UpdateUpnpPinholes();
        }
        else {
            printf("GameStream is disabled\n");
        }

        printf("Going to sleep...\n");
        fflush(stdout);

        HANDLE objects[] = { ifaceChangeEvent, gameStreamStateChangeEvent };
        switch (WaitForMultipleObjects(2, objects, FALSE, 120 * 1000)) {
        case WAIT_OBJECT_0:
            // Interface state changed. Update pinholes immediately.
            ResetLogFile(standaloneExe);
            printf("Woke up for network interface change\n");
            break;
        case WAIT_OBJECT_0 + 1:
            // GameStream state changed
            ResetLogFile(standaloneExe);
            printf("Woke up for GameStream state change\n");

            ResetEvent(gameStreamStateChangeEvent);

            // Shutdown all relay sockets to trigger the relay threads to terminate.
            // The relay threads will call closesocket().
            for (int i = 0; i < ARRAYSIZE(tcpSockets); i++) {
                if (tcpSockets[i] != NULL && tcpSockets[i] != INVALID_SOCKET) {
                    shutdown(tcpSockets[i], SD_BOTH);
                    CancelIoEx((HANDLE)tcpSockets[i], NULL);
                    tcpSockets[i] = INVALID_SOCKET;
                }
            }
            for (int i = 0; i < ARRAYSIZE(udpSockets); i++) {
                if (udpSockets[i] != NULL && udpSockets[i] != INVALID_SOCKET) {
                    shutdown(udpSockets[i], SD_BOTH);
                    CancelIoEx((HANDLE)udpSockets[i], NULL);
                    udpSockets[i] = INVALID_SOCKET;
                }
            }

            // If GameStream is now enabled, start the relay
            if (IsGameStreamEnabled()) {
                StartRelay(tcpSockets, udpSockets);
            }
            else {
                printf("Stopped relay after GameStream was disabled\n");
            }
            break;
        case WAIT_TIMEOUT:
            // Time to refresh the pinholes
            ResetLogFile(standaloneExe);
            printf("Woke up on refresh timer\n");
            break;
        case WAIT_FAILED:
            return -1;
        }

    }

    return 0;
}

static SERVICE_STATUS_HANDLE ServiceStatusHandle;
static SERVICE_STATUS ServiceStatus;

DWORD
WINAPI
HandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    switch (dwControl)
    {
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    case SERVICE_CONTROL_STOP:
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        return NO_ERROR;

    default:
        return NO_ERROR;
    }
}

VOID
WINAPI
ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
    int err;
    
    ServiceStatusHandle = RegisterServiceCtrlHandlerEx(SERVICE_NAME, HandlerEx, NULL);
    if (ServiceStatusHandle == NULL) {
        printf("RegisterServiceCtrlHandlerEx() failed: %d\n", GetLastError());
        return;
    }

    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwWin32ExitCode = NO_ERROR;
    ServiceStatus.dwWaitHint = 0;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    ServiceStatus.dwCheckPoint = 0;

    // Tell SCM we're running
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

    // Start the relay
    err = Run(false);
    if (err != 0) {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        ServiceStatus.dwWin32ExitCode = err;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        return;
    }
}


static const SERVICE_TABLE_ENTRY ServiceTable[] = {
    { SERVICE_NAME, ServiceMain },
    { NULL, NULL }
};

int main(int argc, char* argv[])
{
    if (argc == 2 && !strcmp(argv[1], "exe")) {
        Run(true);
        return 0;
    }

    return StartServiceCtrlDispatcher(ServiceTable);
}

#else // Linux implementation

// Linux: Use /proc/net/route or netlink for getting gateway info
// For simplicity, we'll use a simpler approach that reads routing info

void UpdatePcpPinholes()
{
    struct ifaddrs *ifaddr, *ifa;
    FILE *routeFile;
    char line[256];
    char gateway[64] = {0};
    int foundGateway = 0;
    
    // Try to find the default IPv6 gateway from /proc/net/ipv6_route
    routeFile = fopen("/proc/net/ipv6_route", "r");
    if (routeFile != NULL) {
        while (fgets(line, sizeof(line), routeFile)) {
            // Look for default route (destination 00000000000000000000000000000000)
            if (strncmp(line, "00000000000000000000000000000000", 32) == 0) {
                // Parse gateway from the route entry
                char destNet[33], destPrefix[3], srcNet[33], srcPrefix[3], nextHop[33];
                if (sscanf(line, "%32s %2s %32s %2s %32s", destNet, destPrefix, srcNet, srcPrefix, nextHop) >= 5) {
                    if (strcmp(nextHop, "00000000000000000000000000000000") != 0) {
                        // Convert hex gateway to IPv6 address string
                        struct in6_addr addr;
                        for (int i = 0; i < 16; i++) {
                            unsigned int byte;
                            sscanf(nextHop + i*2, "%2x", &byte);
                            addr.s6_addr[i] = byte;
                        }
                        inet_ntop(AF_INET6, &addr, gateway, sizeof(gateway));
                        foundGateway = 1;
                        break;
                    }
                }
            }
        }
        fclose(routeFile);
    }

    if (!foundGateway) {
        printf("No IPv6 gateway found for PCP\n");
        return;
    }

    printf("Using PCP server: %s\n", gateway);

    // Get all IPv6 addresses and create PCP mappings
    if (getifaddrs(&ifaddr) == -1) {
        printf("getifaddrs() failed: %d\n", errno);
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)ifa->ifa_addr;

        // Exclude link-local addresses
        if (currentAddrV6->sin6_scope_id == 0 && 
            !IN6_IS_ADDR_LINKLOCAL(&currentAddrV6->sin6_addr)) {
            char addressStr[128];
            inet_ntop(AF_INET6, &currentAddrV6->sin6_addr, addressStr, sizeof(addressStr));
            printf("Updating PCP mappings for address %s\n", addressStr);

            // Create gateway address structure
            SOCKADDR_IN6 gatewayAddr;
            memset(&gatewayAddr, 0, sizeof(gatewayAddr));
            gatewayAddr.sin6_family = AF_INET6;
            inet_pton(AF_INET6, gateway, &gatewayAddr.sin6_addr);

            for (size_t i = 0; i < ARRAYSIZE(TCP_PORTS); i++) {
                PCPMapPort(
                    (PSOCKADDR_STORAGE)currentAddrV6,
                    sizeof(*currentAddrV6),
                    (PSOCKADDR_STORAGE)&gatewayAddr,
                    sizeof(gatewayAddr),
                    IPPROTO_TCP,
                    TCP_PORTS[i],
                    true,
                    false);
            }
            for (size_t i = 0; i < ARRAYSIZE(UDP_PORTS); i++) {
                PCPMapPort(
                    (PSOCKADDR_STORAGE)currentAddrV6,
                    sizeof(*currentAddrV6),
                    (PSOCKADDR_STORAGE)&gatewayAddr,
                    sizeof(gatewayAddr),
                    IPPROTO_UDP,
                    UDP_PORTS[i],
                    true,
                    false);
            }
        }
    }

    freeifaddrs(ifaddr);
}

void ResetLogFile(bool standaloneExe)
{
    char timeString[256] = {};
    time_t now;
    struct tm *tm_info;

    if (!standaloneExe) {
        const char* logDir = "/var/log/gsv6fwd";
        char oldLogFilePath[256];
        char currentLogFilePath[256];

        // Create log directory if it doesn't exist
        mkdir(logDir, 0755);

        snprintf(oldLogFilePath, sizeof(oldLogFilePath), "%s/GSv6Fwd-old.log", logDir);
        snprintf(currentLogFilePath, sizeof(currentLogFilePath), "%s/GSv6Fwd-current.log", logDir);

        // Rotate the current to the old log file
        rename(currentLogFilePath, oldLogFilePath);

        // Redirect stdout to this new file
        if (freopen(currentLogFilePath, "w", stdout) == NULL) {
            // If we couldn't create a log file, just redirect stdout to /dev/null.
            FILE* devnull = freopen("/dev/null", "w", stdout);
            (void)devnull;  // Suppress unused variable warning
        }
    }

    // Print a log header
    printf("IPv6 Forwarder for GameStream v" VER_VERSION_STR "\n");

    // Print the current time
    time(&now);
    tm_info = gmtime(&now);
    strftime(timeString, sizeof(timeString), "%H:%M:%S", tm_info);
    printf("The current UTC time is: %s\n", timeString);
}

void StartRelay(SOCKET* tcpSockets, SOCKET* udpSockets) {
    int err;

    for (size_t i = 0; i < ARRAYSIZE(TCP_PORTS); i++) {
        err = StartTcpRelay(TCP_PORTS[i], &tcpSockets[i]);
        if (err != 0) {
            printf("Failed to start relay on TCP %d: %d\n", TCP_PORTS[i], err);
            tcpSockets[i] = INVALID_SOCKET;
        }
    }

    for (size_t i = 0; i < ARRAYSIZE(UDP_PORTS); i++) {
        err = StartUdpRelay(UDP_PORTS[i], &udpSockets[i * 2], &udpSockets[i * 2 + 1]);
        if (err != 0) {
            printf("Failed to start relay on UDP %d: %d\n", UDP_PORTS[i], err);
            udpSockets[i * 2] = udpSockets[i * 2 + 1] = INVALID_SOCKET;
        }
    }
}

static volatile int g_running = 1;

void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

int Run(bool standaloneExe)
{
    ResetLogFile(standaloneExe);

    // Keep track of TCP and UDP sockets for the relays.
    SOCKET tcpSockets[ARRAYSIZE(TCP_PORTS)] = {INVALID_SOCKET};
    SOCKET udpSockets[ARRAYSIZE(UDP_PORTS) * 2] = {INVALID_SOCKET};

    // On Linux, we always start the relay (no GameStream registry check)
    printf("Starting IPv6 relay...\n");
    StartRelay(tcpSockets, udpSockets);

    // Setup signal handler for graceful shutdown
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    while (g_running) {
        printf("Updating UPnP/PCP pinholes...\n");
        UpdatePcpPinholes();
        UpdateUpnpPinholes();

        printf("Going to sleep...\n");
        fflush(stdout);

        // Sleep for 120 seconds (same as Windows), checking for shutdown periodically
        for (int i = 0; i < 120 && g_running; i++) {
            sleep(1);
        }

        if (g_running) {
            ResetLogFile(standaloneExe);
            printf("Woke up on refresh timer\n");
        }
    }

    printf("Shutting down...\n");

    // Close all sockets
    for (size_t i = 0; i < ARRAYSIZE(tcpSockets); i++) {
        if (tcpSockets[i] != INVALID_SOCKET) {
            shutdown(tcpSockets[i], SHUT_RDWR);
            close(tcpSockets[i]);
        }
    }
    for (size_t i = 0; i < ARRAYSIZE(udpSockets); i++) {
        if (udpSockets[i] != INVALID_SOCKET) {
            shutdown(udpSockets[i], SHUT_RDWR);
            close(udpSockets[i]);
        }
    }

    return 0;
}

int main(int argc, char* argv[])
{
    bool daemon_mode = false;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemon") == 0) {
            daemon_mode = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -d, --daemon    Run as daemon (background)\n");
            printf("  -h, --help      Show this help message\n");
            printf("\nIPv6 Forwarder for GameStream - Allows Moonlight clients to connect over IPv6\n");
            return 0;
        }
    }

    if (daemon_mode) {
        // Daemonize
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed");
            return 1;
        }
        if (pid > 0) {
            // Parent exits
            return 0;
        }
        // Child continues
        setsid();
        
        // Close standard file descriptors
        close(STDIN_FILENO);
        
        Run(false);
    } else {
        Run(true);
    }

    return 0;
}

#endif // _WIN32

