package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"httpt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	tls "github.com/refraction-networking/utls"
)

// TODO: clean up descriptions
var mode = flag.String("mode", "http", "transparent/http.")
var debug = flag.Bool("debug", true, "Enable debug output.")
var port = flag.Int("port", 4714, "Port for local transparent proxy")
var addr = flag.String("addr", "52.33.220.110:443", "")
var sni = flag.String("sni", "sfrolov.io", "")
var secretLink = flag.String("secret", "secretLink", "")

var bufferSize = flag.Int("buffer", 0, "Size of buffer (in KB) for local buffering per connection. Set to 0 to turn off.")

// TODO: try using/expanding the HTTPS client: use github.com/caddyserver/forwardproxy/httpclient ?

var tlsDialer *tls.Roller

// TODO: make error print vs dont before exit consistent
func DialWS(addr string, args map[string]string, targetAddr string, hello []byte) (net.Conn, []byte, error) {
	serverName, ok := args["serverName"]
	if !ok || serverName == "" {
		err := errors.New("serverName argument is missing")
		log.Println(err)
		return nil, nil, err
	}

	secretLink, ok := args["secretLink"]
	if !ok || secretLink == "" {
		err := errors.New("secretLink argument is missing")
		log.Println(err)
		return nil, nil, err
	}

	//    // if reframerID is nil, creates new connection to reframer server
	//    establish TLS to server
	//    send HTTP/1.1 WS request. It will include the ID to reconnect, if reconnecting
	//    WS response will include in the headers the InitialState or ReconnectState
	conn, err := tlsDialer.Dial("tcp", addr, serverName)
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}

	log.Printf("[uTLS] mimicking %v. ALPN offered: %v, chosen: %v\n",
		conn.ClientHelloID.Str(), conn.HandshakeState.Hello.AlpnProtocols, conn.HandshakeState.ServerHello.AlpnProtocol)

	switch conn.HandshakeState.ServerHello.AlpnProtocol {
	case "http/1.1", "":
		req, err := http.NewRequest("GET", "/"+secretLink, nil)
		if err != nil {
			log.Println(err)
			return nil, nil, err
		}
		req.Host = serverName

		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("X-ReframerCH", base64.StdEncoding.EncodeToString(hello))
		req.Header.Set("X-TargetAddr", targetAddr)

		// TODO: req.Header.Set("X-Padding", "[][]")

		err = req.Write(conn)
		if err != nil {
			log.Printf("failed to write WebSocket Upgrade Request: %v\n", err)
			return nil, nil, err
		}
		log.Println("DEBUG wrote req, err", err)

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			log.Println(err)
			return nil, nil, err
		}

		if resp.Status == "101 Switching Protocols" &&
			strings.ToLower(resp.Header.Get("Upgrade")) == "websocket" &&
			strings.ToLower(resp.Header.Get("Connection")) == "upgrade" {

			serverHello, err := base64.StdEncoding.DecodeString(resp.Header.Get("X-ReframerSH"))
			if err != nil {
				return nil, nil, err
			}

			return conn, serverHello, nil
		} else {
			respBytes, err := httputil.DumpResponse(resp, false)
			if err != nil {
				log.Println(err)
				return nil, nil, err
			}
			err = errors.New("Got unexpected response:\n" + string(respBytes) + "\nstatus:" + resp.Status)
			log.Println(err)
			return nil, nil, err
		}
	case "h2":
		return nil, nil, errors.New("http2 is not implemented yet")
	default:
		return nil, nil, errors.New("Unknown ALPN: " + conn.HandshakeState.ServerHello.AlpnProtocol)
	}

	return nil, nil, err
}

func main() {
	flag.Parse()

	if *debug {
		log.SetFlags(log.Lmicroseconds | log.Lshortfile)
	} else {
		log.SetFlags(log.Lmicroseconds | log.Ldate)
	}
	log.SetPrefix("[init] ")

	// hook up Reframer with:
	// func DialWS(id connectionID)
	var err error
	tlsDialer, err = tls.NewRoller()
	if err != nil {
		log.Fatal(err)
	}

	// Remove all ClientHellos that have ALPN, as h2 is not supported yet.
	// TODO: remove next line when h2 is implemented
	//tlsDialer.HelloIDs = []tls.ClientHelloID{tls.HelloChrome_58}
	tlsDialer.HelloIDs = []tls.ClientHelloID{tls.HelloRandomizedNoALPN}

	switch *mode {
	case "test":
		//conn, err := DialWS(0, "52.33.220.110:443", map[string]string{"serverName" : "sfrolov.io",
		//	"secretLink" : "secretLink"})
		//if err != nil {
		//	log.Fatalln(err)
		//}
		//_ = DialWS(0, "52.33.220.110:2443", map[string]string{"serverName" : "sfrolov.io",
		//	"secretLink" : "secretLink"})
		//_ = DialWS(0, "52.33.220.110:3443", map[string]string{"serverName" : "sfrolov.io",
		//	"secretLink" : "secretLink"})
	case "http":
		ln, err := net.Listen("tcp", "localhost:"+strconv.Itoa(*port))
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("Listening for incoming connections on", ln.Addr().String())
		// TODO: more info where connecting and with which options

		log.SetPrefix("[runtime] ")
		for {
			clientConn, err := ln.Accept()
			if err != nil {
				log.Println("Failed to accept connection:", err)
				continue
			}
			go handleConn(clientConn)
		}
	case "transparent":
	default:
		panic("unknown mode")
	}
}

func handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	log.SetPrefix("[" + clientConn.RemoteAddr().String() + "] ")

	req, err := http.ReadRequest(bufio.NewReader(clientConn))
	if err != nil {
		log.Println(err)
		return
	}

	if req.Method != "CONNECT" {
		dump, dumpErr := httputil.DumpRequest(req, true)
		log.Println("unexpected request", dump, "\nerror:", dumpErr)
		return
	}

	res := &http.Response{StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	err = res.Write(clientConn)
	if err != nil {
		log.Fatalln(err)
	}

	hello := make([]byte, 1024)
	n, err := clientConn.Read(hello)
	if err != nil {
		log.Println("failed to read client hello:", hello)
		return
	}

	serverConn, _, err := DialWS(*addr, map[string]string{"serverName": *sni,
		"secretLink": *secretLink}, req.RequestURI, hello[:n])
	if err != nil {
		log.Fatalln(err)
	}

	httpt.TransparentProxy(clientConn, serverConn)
}
