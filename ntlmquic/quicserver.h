#pragma once
#include <stdio.h>
#include <stdlib.h>
#include "msquic.h"
#include "msquic_winuser.h"
#include <wincrypt.h>
#include "utils.h"
#include "tcpclient.h"

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
	QUIC_CREDENTIAL_CONFIG CredConfig;
	union {
		QUIC_CERTIFICATE_HASH CertHash;
		QUIC_CERTIFICATE_HASH_STORE CertHashStore;
		QUIC_CERTIFICATE_FILE CertFile;
	};
} QUIC_CREDENTIAL_CONFIG_HELPER;

const uint64_t IdleTimeoutMs = 10000;
const QUIC_BUFFER Alpn = { sizeof("smb") - 1, (uint8_t*)"smb" };
const QUIC_REGISTRATION_CONFIG RegConfig = { "ntlmQUIC", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

class QuicServer {
private:
	uint16_t _port;
	const char* _relayIP;
	uint16_t _relayPort;
	const char* _path;
	const char* _privatePath;
	const char* _hash;

	HQUIC _listener = NULL;
	HQUIC _registration = NULL;
	HQUIC _configuration = NULL;

	static QUIC_STATUS QUIC_API ServerStreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event);
	static QUIC_STATUS QUIC_API	ServerConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event);
	static QUIC_STATUS QUIC_API	ServerListenerCallback(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event);

	BOOLEAN ServerLoadConfiguration(const char* hash, const char* path, const char* pathPrivate);

public:
	QuicServer(uint16_t port, const char* relayIP, uint16_t relayPort, const char* path, const char* privatePath) :_port(port), _path(path), _relayIP(relayIP), _relayPort(relayPort), _privatePath(privatePath) {}
	QuicServer(uint16_t port, const char* relayIP, uint16_t relayPort, const char* hash) :_port(port), _relayIP(relayIP), _relayPort(relayPort), _hash(hash) {}

	void Start(void);
	void Stop(void);
};