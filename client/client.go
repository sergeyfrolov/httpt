package main

import (
	"bufio"
	"errors"
	tls "github.com/refraction-networking/utls"
	"log"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
)

// TODO: try using/expanding the HTTPS client: use github.com/caddyserver/forwardproxy/httpclient ?

var tlsDialer *tls.Roller

func DialWS(id int, addr string, args map[string]string) error {
	serverName, ok := args["serverName"]
	if !ok || serverName == "" {
		err := errors.New("serverName argument is missing")
		log.Println(err)
		return err
	}

	secretLink, ok := args["secretLink"]
	if !ok || secretLink == "" {
		err := errors.New("secretLink argument is missing")
		log.Println(err)
		return err
	}

	//    // if id is nil, creates new connection to reframer server
	//    establish TLS to server
	//    send HTTP/1.1 WS request. It will include the ID to reconnect, if reconnecting
	//    WS response will include in the headers the InitialState or ReconnectState
	conn, err := tlsDialer.Dial("tcp", addr, serverName)
	if err != nil {
		log.Println(err)
		return err
	}

	log.Printf("[uTLS] mimicking %v. ALPN offered: %v, chosen: %v\n",
		conn.ClientHelloID.Str(), conn.HandshakeState.Hello.AlpnProtocols, conn.HandshakeState.ServerHello.AlpnProtocol)

	switch conn.HandshakeState.ServerHello.AlpnProtocol {
	case "http/1.1", "":
		req, err := http.NewRequest("GET", "/" + secretLink, nil)
		if err != nil {
			log.Println(err)
			return err
		}
		req.Host = serverName
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("X-Reframer-Id", strconv.Itoa(id))

		// TODO: req.Header.Set("X-Padding", "[][]")

		err = req.Write(conn)
		if err != nil {
			log.Printf("failed to write WebSocket Upgrade Request: %v\n", err)
			return err
		}
		log.Println("DEBUG wrote req, err", err)

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			log.Println(err)
			return err
		}

		if resp.Status == "101 Switching Protocols" &&
			strings.ToLower(resp.Header.Get("Upgrade")) == "websocket" &&
			strings.ToLower(resp.Header.Get("Connection")) == "upgrade" {
			_, err = conn.Write([]byte("hi, I am PT client!"))
			if err != nil {
				log.Println(err)
				return err
			}

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			log.Println(string(buf[:n]), err)
		} else {
			respBytes, err := httputil.DumpResponse(resp, false)
			if err != nil {
				log.Println(err)
				return err
			}
			err = errors.New("Got unexpected response:\n" + string(respBytes) + "\nstatus:" +resp.Status)
			log.Println(err)
			return err
		}
	case "h2":
		log.Printf("http2 is not implemented yet\n")
		return err
	default:
		log.Println("Unknown ALPN", conn.HandshakeState.ServerHello.AlpnProtocol)
		return err
	}

	return nil
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	// hook up Reframer with:
	// func DialWS(id connectionID)
	var err error
	tlsDialer, err = tls.NewRoller()
	if err != nil {
		log.Fatal(err)
	}

	// Remove all ClientHellos that have ALPN, as h2 is not supported yet.
	// TODO: remove next line when h2 is implemented
	tlsDialer.HelloIDs = []tls.ClientHelloID{tls.HelloRandomizedNoALPN}

	_ = DialWS(0, "52.33.220.110:443", map[string]string{"serverName" : "sfrolov.io",
		"secretLink" : "secretLink"})
	_ = DialWS(0, "52.33.220.110:2443", map[string]string{"serverName" : "sfrolov.io",
		"secretLink" : "secretLink"})
	_ = DialWS(0, "52.33.220.110:3443", map[string]string{"serverName" : "sfrolov.io",
		"secretLink" : "secretLink"})
}
