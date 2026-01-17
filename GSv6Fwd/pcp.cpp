#ifdef _WIN32
#define _CRT_RAND_S
#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "Shlwapi.lib")
#include <shlwapi.h>

#include <assert.h>
#include <stdio.h>

#else // Linux

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket close

typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr_in* PSOCKADDR_IN;
typedef struct sockaddr_in6 SOCKADDR_IN6;
typedef struct sockaddr_in6* PSOCKADDR_IN6;
typedef struct sockaddr_storage SOCKADDR_STORAGE;
typedef struct sockaddr_storage* PSOCKADDR_STORAGE;
typedef unsigned char BYTE;

// Simple hash function for Linux (replacement for Windows HashData)
static void HashData(const BYTE* data, int dataLen, unsigned char* output, int outputLen)
{
    // Simple FNV-1a hash
    unsigned int hash = 2166136261u;
    for (int i = 0; i < dataLen; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    
    // Fill output with hash-derived bytes
    for (int i = 0; i < outputLen; i++) {
        output[i] = (hash >> ((i % 4) * 8)) & 0xFF;
        if ((i % 4) == 3) {
            hash = hash * 16777619u + i;
        }
    }
}

#endif // _WIN32

#define RECV_TIMEOUT_SEC 3

#define PCP_VERSION 2
#define OPCODE_MAP_REQUEST  0x01
#define OPCODE_MAP_RESPONSE 0x81

#define CODE_PREFER_FAILURE 2

#ifdef _WIN32
#pragma pack(push, 1)
#endif

typedef struct _PCP_REQUEST_HEADER {
    unsigned char version;
    unsigned char opcode;
    unsigned short reserved;
    unsigned int lifetime;
    unsigned char localAddress[16];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
PCP_REQUEST_HEADER, *PPCP_REQUEST_HEADER;

typedef struct _PCP_RESPONSE_HEADER {
    unsigned char version;
    unsigned char opcode;
    unsigned char reserved;
    unsigned char result;
    unsigned int lifetime;
    unsigned int epoch;
    unsigned char reserved2[12];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
PCP_RESPONSE_HEADER, *PPCP_RESPONSE_HEADER;

typedef struct _PCP_OPTION_HEADER {
    unsigned char code;
    unsigned char reserved;
    unsigned short length;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
PCP_OPTION_HEADER, *PPCP_OPTION_HEADER;

typedef struct _PCP_MAP_REQUEST {
    PCP_REQUEST_HEADER hdr;

    unsigned char mappingNonce[12];
    unsigned char protocol;
    unsigned char reserved[3];
    unsigned short internalPort;
    unsigned short externalPort;
    unsigned char externalAddress[16];

    // We send PREFER_FAILURE too for MAP requests
    PCP_OPTION_HEADER preferFailureOption;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
PCP_MAP_REQUEST, *PPCP_MAP_REQUEST;

typedef struct _PCP_MAP_RESPONSE {
    PCP_RESPONSE_HEADER hdr;

    unsigned char mappingNonce[12];
    unsigned char protocol;
    unsigned char reserved[3];
    unsigned short internalPort;
    unsigned short externalPort;
    unsigned char externalAddress[16];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
PCP_MAP_RESPONSE, *PPCP_MAP_RESPONSE;

#ifdef _WIN32
#pragma pack(pop)
#endif

static void populateMappingNonce(PPCP_MAP_REQUEST request, PSOCKADDR_STORAGE pcpAddr, int pcpAddrLen)
{
    struct {
        unsigned short port;
        unsigned char localAddress[16];
        SOCKADDR_STORAGE targetAddress;
    } dataToHash;

    assert(request->internalPort != 0);

    dataToHash.port = request->internalPort;
    memcpy(dataToHash.localAddress, request->hdr.localAddress, sizeof(dataToHash.localAddress));
    memcpy(&dataToHash.targetAddress, pcpAddr, pcpAddrLen);

    HashData((BYTE*)&dataToHash, 18 + pcpAddrLen, request->mappingNonce, sizeof(request->mappingNonce));
}

static void populateAddressFromSockAddr(PSOCKADDR_STORAGE sockAddr, unsigned char* address)
{
    if (sockAddr->ss_family == AF_INET) {
        PSOCKADDR_IN sin = (PSOCKADDR_IN)sockAddr;
        memset(&address[0], 0, 10);
        memset(&address[10], 0xFF, 2);
        memcpy(&address[12], &sin->sin_addr, 4);
    }
    else if (sockAddr->ss_family == AF_INET6) {
        PSOCKADDR_IN6 sin6 = (PSOCKADDR_IN6)sockAddr;
        memcpy(address, &sin6->sin6_addr, 16);
    }
    else {
        assert(false);
    }
}

bool PCPMapPort(PSOCKADDR_STORAGE localAddr, int localAddrLen, PSOCKADDR_STORAGE pcpAddr, int pcpAddrLen, int proto, int port, bool enable, bool indefinite)
{
    SOCKET sock;
    PCP_MAP_REQUEST reqMsg;
    int reqMsgLen;
    int i;
    int bytesRead;
    union {
        PCP_MAP_RESPONSE hdr;
        char buf[1100];
    } resp;
    int lifetime;

    if (!enable) {
        lifetime = 0;
    }
    else if (indefinite) {
        lifetime = 604800; // 1 week
    }
    else {
        lifetime = 3600;
    }

    assert(localAddr->ss_family == pcpAddr->ss_family);

    printf("Updating PCP port mapping for %s %d...", proto == IPPROTO_TCP ? "TCP" : "UDP", port);

    sock = socket(localAddr->ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
#ifdef _WIN32
        printf("socket() failed: %d\n", WSAGetLastError());
#else
        printf("socket() failed: %d\n", errno);
#endif
        return false;
    }

    if (localAddr->ss_family == AF_INET6) {
        // Make sure we're sourcing from the correct IPv6 address to ensure the port
        // is opened correctly and that the PCP server doesn't refuse our mapping.
        ((PSOCKADDR_IN6)localAddr)->sin6_port = 0;
        if (bind(sock, (struct sockaddr*)localAddr, localAddrLen) == SOCKET_ERROR) {
#ifdef _WIN32
            printf("bind() failed: %d\n", WSAGetLastError());
#else
            printf("bind() failed: %d\n", errno);
#endif
            closesocket(sock);
            return false;
        }
    }

    ((PSOCKADDR_IN)pcpAddr)->sin_port = htons(5351);
    if (connect(sock, (struct sockaddr*)pcpAddr, pcpAddrLen) == SOCKET_ERROR) {
#ifdef _WIN32
        printf("connect() failed: %d\n", WSAGetLastError());
#else
        printf("connect() failed: %d\n", errno);
#endif
        closesocket(sock);
        return false;
    }

    memset(&reqMsg, 0, sizeof(reqMsg));
    reqMsg.hdr.version = PCP_VERSION;
    reqMsg.hdr.opcode = OPCODE_MAP_REQUEST;
    reqMsg.hdr.lifetime = htonl(lifetime);
    populateAddressFromSockAddr(localAddr, reqMsg.hdr.localAddress);

    reqMsg.protocol = proto;
    reqMsg.internalPort = htons(port);
    reqMsg.externalPort = htons(port);

    SOCKADDR_STORAGE noneAddr;
    memset(&noneAddr, 0, sizeof(noneAddr));
    noneAddr.ss_family = localAddr->ss_family;
    populateAddressFromSockAddr(&noneAddr, reqMsg.externalAddress);

    if (enable) {
        // We don't want an alternate allocation if this fails
        reqMsg.preferFailureOption.code = CODE_PREFER_FAILURE;
        reqMsg.preferFailureOption.length = 0;
        reqMsgLen = sizeof(reqMsg);
    }
    else {
        // We don't append PREFER_FAILURE for an unmap request
        reqMsgLen = sizeof(reqMsg) - sizeof(reqMsg.preferFailureOption);
    }

    // This must be done after the rest of the message is populated
    populateMappingNonce(&reqMsg, pcpAddr, pcpAddrLen);

    bytesRead = 0;
    for (i = 0; i < RECV_TIMEOUT_SEC; i++) {
        // Retransmit the request every second until the timeout elapses
        if (send(sock, (char *)&reqMsg, reqMsgLen, 0) == SOCKET_ERROR) {
#ifdef _WIN32
            printf("send() failed: %d\n", WSAGetLastError());
#else
            printf("send() failed: %d\n", errno);
#endif
            closesocket(sock);
            return false;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

#ifdef _WIN32
        int selectRes = select(0, &fds, NULL, NULL, &tv);
#else
        int selectRes = select(sock + 1, &fds, NULL, NULL, &tv);
#endif
        if (selectRes == 0) {
            // Timeout - continue looping
            continue;
        }
        else if (selectRes == SOCKET_ERROR) {
#ifdef _WIN32
            printf("select() failed: %d\n", WSAGetLastError());
#else
            printf("select() failed: %d\n", errno);
#endif
            closesocket(sock);
            return false;
        }

        // Error handling is below
        bytesRead = recv(sock, resp.buf, sizeof(resp.buf), 0);
        break;
    }

    if (bytesRead == 0) {
        printf("NO RESPONSE\n");
        goto fail;
    }
    else if (bytesRead == SOCKET_ERROR) {
#ifdef _WIN32
        printf("Failed to read PCP response: %d\n", WSAGetLastError());
#else
        printf("Failed to read PCP response: %d\n", errno);
#endif
        goto fail;
    }
    else if (bytesRead < (int)sizeof(resp.hdr)) {
        printf("PCP message truncated: %d\n", bytesRead);
        goto fail;
    }
    else if (resp.hdr.hdr.version != PCP_VERSION) {
        printf("PCP version mismatch: %x\n", resp.hdr.hdr.version);
        goto fail;
    }
    else if (resp.hdr.hdr.opcode != OPCODE_MAP_RESPONSE) {
        printf("PCP message type mismatch: %x\n", resp.hdr.hdr.opcode);
        goto fail;
    }
    else if (resp.hdr.hdr.result != 0) {
        switch (resp.hdr.hdr.result) {
        case 1: // UNSUPP_VERSION
            printf("UNSUPPORTED\n");
            break;
        case 2: // NOT_AUTHORIZED
            printf("UNAUTHORIZED\n");
            break;
        case 11: // CANNOT_PROVIDE_EXTERNAL
            printf("CONFLICT\n");
            break;
        default:
            printf("ERROR: %d\n", resp.hdr.hdr.result);
            break;
        }
        goto fail;
    }
    else if (memcmp(reqMsg.mappingNonce, resp.hdr.mappingNonce, sizeof(reqMsg.mappingNonce))) {
        printf("PCP mapping nonce mismatch\n");
        goto fail;
    }
    else if (reqMsg.protocol != resp.hdr.protocol) {
        printf("PCP protocol mismatch: %d wanted %d\n", resp.hdr.protocol, reqMsg.protocol);
        goto fail;
    }
    else if (reqMsg.internalPort != resp.hdr.internalPort) {
        printf("PCP internal port mismatch: %d wanted %d\n", htons(resp.hdr.internalPort), htons(reqMsg.internalPort));
        goto fail;
    }
    else if (reqMsg.externalPort != resp.hdr.externalPort) {
        printf("PCP returned different external port: %d wanted %d\n", htons(resp.hdr.externalPort), htons(reqMsg.externalPort));
        if (enable) {
            // Clear the port mapping by modifying and resending the old request (with the same nonce)
            reqMsg.hdr.lifetime = 0;
            reqMsg.externalPort = resp.hdr.externalPort;
            reqMsgLen = sizeof(reqMsg) - sizeof(reqMsg.preferFailureOption);
            if (send(sock, (char*)&reqMsg, reqMsgLen, 0) == SOCKET_ERROR) {
#ifdef _WIN32
                printf("Failed to unmap unexpected external port: %d\n", WSAGetLastError());
#else
                printf("Failed to unmap unexpected external port: %d\n", errno);
#endif
            }
        }
        goto fail;
    }

    if (enable) {
        printf("OK (%d seconds remaining)\n", ntohl(resp.hdr.hdr.lifetime));
    }
    else {
        printf("DELETED\n");
    }

    closesocket(sock);
    return true;

fail:
    closesocket(sock);
    return false;
}