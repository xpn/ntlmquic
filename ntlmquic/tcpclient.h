#pragma once
#include <Windows.h>

class TcpClient {
private:
	int _port;
	const char* _host;
	SOCKET _sock;

public:
	TcpClient(const char* host, int port);
	bool Connect();
	int Send(char* buffer, int len);
	int Recv(char* buffer, int len);
};