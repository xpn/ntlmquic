#include "quicserver.h"

const QUIC_API_TABLE* MsQuic;

#define MAX_BUFFER_SIZE 9000
#define DEFAULT_CERT_STORE "MY"

QUIC_STATUS QUIC_API QuicServer::ServerStreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {
    void* SendBufferRaw;
    QUIC_BUFFER* sb;
    int dataLen;
    TcpClient* tcpClient;
    char* buffer;

    tcpClient = static_cast<TcpClient*>(Context);
    if (tcpClient == NULL) {
        printf("[!] Error retrieving tcpClient from Context\n");
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    switch (Event->Type) {
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            free(Event->SEND_COMPLETE.ClientContext);
            break;
        case QUIC_STREAM_EVENT_RECEIVE:

            SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + MAX_BUFFER_SIZE);
            sb = (QUIC_BUFFER*)SendBufferRaw;
            buffer = ((char *)SendBufferRaw + sizeof(QUIC_BUFFER));

            for (int i = 0; i < Event->RECEIVE.BufferCount; i++) {
               tcpClient->Send((char *)Event->RECEIVE.Buffers[i].Buffer, Event->RECEIVE.Buffers[i].Length);
            }

            dataLen = tcpClient->Recv(buffer, MAX_BUFFER_SIZE);
        
            sb->Buffer = (uint8_t*)buffer;
            sb->Length = dataLen;

            MsQuic->StreamSend(Stream, sb, 1, QUIC_SEND_FLAG_NONE, sb);
        
            printf("[*] Data Received From Client\n");
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            printf("[*] Peer Closed Stream\n");
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            printf("[*] Peer Aborted Stream\n");
            MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            printf("[*] Done\n");
            MsQuic->StreamClose(Stream);
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API QuicServer::ServerConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {

    TcpClient* tcpClient = NULL;
    QuicServer* quicServer = static_cast<QuicServer*>(Context);

    if (quicServer == NULL) {
        printf("[!] Error retrieving QuicServer from Context\n");
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            printf("[*] Connection received\n");

            MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
                printf("[*] Idle connection terminated\n");
            }
            else {
                printf("[*] Connection shut down by transport [0x%p]\n", Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
            }
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            printf("[*] Connection closed by peer\n");
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            MsQuic->ConnectionClose(Connection);
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:

            tcpClient = new TcpClient(quicServer->_relayIP, quicServer->_relayPort);
            if (!tcpClient->Connect()) {
                printf("[!] Error connecting to TCP SMB forwarder\n");
                return QUIC_STATUS_ABORTED;
            }

            printf("[*] New Stream Started\n");

            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)QuicServer::ServerStreamCallback, (void*)tcpClient);
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API QuicServer::ServerListenerCallback(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) {
	QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    QuicServer* quicServer = static_cast<QuicServer*>(Context);

    if (quicServer == NULL) {
        printf("[!] Error retrieving QuicServer from Context\n");
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    switch (Event->Type) {
	    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
		    MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, Context);
		    Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, quicServer->_configuration);
		    break;
	    default:
		    break;
	}

	return Status;
}

BOOLEAN QuicServer::ServerLoadConfiguration(const char *hash, const char *path, const char *pathPrivate) {
    QUIC_SETTINGS Settings = { 0 };
    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    memset(&Config, 0, sizeof(Config));

    if (hash != NULL) {
        Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
        Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE;

        uint32_t CertHashLen = DecodeHexBuffer(hash, sizeof(Config.CertHashStore.ShaHash), Config.CertHashStore.ShaHash);
        if (CertHashLen != sizeof(Config.CertHashStore.ShaHash)) {
            return FALSE;
        }

        strncpy_s(Config.CertHashStore.StoreName, DEFAULT_CERT_STORE, 2);
        Config.CertHashStore.Flags = QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE;
        Config.CredConfig.CertificateHashStore = &Config.CertHashStore;
    }
    else {
        Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
        Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
        Config.CertFile.CertificateFile = this->_path;
        Config.CertFile.PrivateKeyFile = this->_privatePath;
        Config.CredConfig.CertificateFile = &Config.CertFile;
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(this->_registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &this->_configuration))) {
        printf("[!] ConfigurationOpen error [0x%x]\n", Status);
        return FALSE;
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(this->_configuration, &Config.CredConfig))) {
        printf("[!] ConfigurationLoadCredential error [0x%x]\n", Status);
        return FALSE;
    }

    return TRUE;
}

void QuicServer::Start(void) {

	QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_ADDR Address = { 0 };

	if (QUIC_FAILED(Status = MsQuicOpen(&MsQuic))) {
		printf("[!] MsQuicOpen error [0x%x]\n", Status);
		return;
	}

	if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &this->_registration))) {
		printf("[!] RegistrationOpen error [0x%x]\n", Status);
        return;
	}

	QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
	QuicAddrSetPort(&Address, this->_port);
    
    if (!this->ServerLoadConfiguration(this->_hash, this->_path, this->_privatePath)) {
        printf("[!] ServerLoadConifguration error\n");
        return;
    }

	if (QUIC_FAILED(Status = MsQuic->ListenerOpen(this->_registration, ServerListenerCallback, this, &this->_listener))) {
		printf("[!] ListenerOpen error [0x%x]\n", Status);
        return;
    }

	if (QUIC_FAILED(Status = MsQuic->ListenerStart(this->_listener, &Alpn, 1, &Address))) {
		printf("[!] ListenerStart error [0x%x]\n", Status);
        return;
    }
}

void QuicServer::Stop(void) {
    MsQuic->ListenerClose(this->_listener);
    MsQuicClose(MsQuic);
}