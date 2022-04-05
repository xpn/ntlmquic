package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/lucas-clemente/quic-go"
)

func main() {

	// Set up our TLS
	tlsConfig, err := configureTLS()
	if err != nil {
		fmt.Println("[!] Error grabbing TLS certs")
		return
	}

	// We're listening on UDP/443 for this
	listener, err := quic.ListenAddr("0.0.0.0:443", tlsConfig, nil)
	if err != nil {
		fmt.Println("[!] Error binding to UDP/443")
		return
	}

	fmt.Println("[*] Started listening on UDP/443")

	// Accept inbound connection
	session, err := listener.Accept(context.Background())
	if err != nil {
		fmt.Println("Error accepting connection from client")
		return
	}

	fmt.Printf("[*] Accepted connection: %s\n", session.RemoteAddr().String())

	// Setup stream
	_, err = session.AcceptStream(context.Background())
	if err != nil {
		fmt.Println("Error accepting stream from QUIC client")
	}

	fmt.Printf("[*] Stream setup successfully with: %s\n", session.RemoteAddr().String())
}

func configureTLS() (*tls.Config, error) {

	cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, fmt.Errorf("Could not load server.crt and server.key")
	}

	// ALPN as SMB
	return &tls.Config{
		Certificates: []tls.Certificate{cer},
		NextProtos:   []string{"smb"},
	}, nil
}
