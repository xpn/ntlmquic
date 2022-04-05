package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/lucas-clemente/quic-go"
)

const BUFFER_SIZE = 11000

func startQuicServer(tlsConfig *tls.Config) error {
	quicListener, err := quic.ListenAddr("0.0.0.0:443", tlsConfig, nil)
	if err != nil {
		return fmt.Errorf("Error binding to UDP/443")
	}

	fmt.Println("[*] Started listening on UDP/443")

	for {
		session, err := quicListener.Accept(context.Background())
		if err != nil {
			fmt.Println("[!] Error accepting connection from client")
			continue
		}

		fmt.Printf("[*] Accepted connection from %s\n", session.RemoteAddr().String())

		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			fmt.Println("[!] Error accepting stream from QUIC client")
		}

		go func() {
			tcpConnection, err := net.Dial("tcp", "localhost:445")
			if err != nil {
				fmt.Println("[!] Error connecting to localhost:445")
				return
			}

			fmt.Println("[*] Connected to localhost:445\n[*] Starting relaying process...")

			dataBuffer := make([]byte, BUFFER_SIZE)

			for {

				dataCount, err := stream.Read(dataBuffer)
				if err != nil {
					return
				}

				dataCount, err = tcpConnection.Write(dataBuffer[0:dataCount])
				if err != nil || dataCount == 0 {
					return
				}

				dataCount, err = tcpConnection.Read(dataBuffer)
				if err != nil {
					return
				}

				dataCount, err = stream.Write(dataBuffer[0:dataCount])
				if err != nil || dataCount == 0 {
					return
				}
			}
		}()
	}

	return nil
}

func main() {

	fmt.Println("SMB over QUIC Termination POC by @_xpn_")

	tlsConfig, err := configureTLS()
	if err != nil {
		fmt.Println("[!] Error grabbing TLS certs")
		return
	}

	err = startQuicServer(tlsConfig)
	if err != nil {
		fmt.Println("[!] " + err.Error())
	}
}

func configureTLS() (*tls.Config, error) {

	cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, fmt.Errorf("Could not load server.crt and server.key")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cer},
		NextProtos:   []string{"smb"},
	}, nil
}
