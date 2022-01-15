#include "tcpclient.h"

TcpClient::TcpClient(const char* host, int port) {
	this->_host = host;
	this->_port = port;
	this->_sock = NULL;
}

bool TcpClient::Connect() {

	WSADATA wsd;
	SOCKADDR_IN sin;

	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
		return FALSE;
	}

	this->_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (this->_sock == SOCKET_ERROR) {
		return FALSE;
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons(this->_port);
	sin.sin_addr.S_un.S_addr = inet_addr(this->_host);

	if (connect(this->_sock, (SOCKADDR*)&sin, sizeof(sin)) == SOCKET_ERROR) {
		return FALSE;
	}

	return TRUE;
}

int TcpClient::Send(char* buffer, int len) {
	if (buffer == NULL || len == 0) {
		return -1;
	}

	return send(this->_sock, buffer, len, 0);
}

int TcpClient::Recv(char* buffer, int len) {
	if (buffer == NULL || len == 0) {
		return -1;
	}

	return recv(this->_sock, buffer, len, 0);

}