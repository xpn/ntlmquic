#include <iostream>
#include "quicserver.h"

int main(int argc, char **argv)
{
    printf("ntlmQUIC POC by @_xpn_\n");
    QuicServer* server;

    if (argc == 4) {
        printf("[*] Starting server\n[*] Forwarding QUIC over SMB to %s:%s\n", argv[1], argv[2]);
        server = new QuicServer(443, argv[1], atoi(argv[2]), argv[3]);
    }
    else if (argc == 5) {
        printf("[*] Starting server\n[*] Forwarding QUIC over SMB to %s:%s\n", argv[1], argv[2]);
        server = new QuicServer(443, argv[1], atoi(argv[2]), argv[3], argv[4]);// "server.cert", "server.key");
    }
    else {
        printf("Usage: %s FORWARD_IP FORWARD_PORT CERT_HASH\n", argv[0]);
        printf("Usage: %s FORWARD_IP FORWARD_PORT CERT_FILENAME KEY_FILENAME\n", argv[0]);
        return 1;
    }

    server->Start();

    printf("[?] Hit Enter To Stop\n");
    getchar();

    server->Stop();
}