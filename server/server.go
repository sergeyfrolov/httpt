package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"httpt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

var secretLink = flag.String("secret-link", "secretLink", "TODO")           // TODO: description
var debug = flag.Bool("debug", true, "Enable debug output. Default: TODO.") // TODO
var statsPeriod = flag.Int("stats-period", 1, "Period in minutes for printing aggregate stats."+
	"Set to 0 to disable aggregate stats printing. Default: 1 minute.")
var addr = flag.String("addr", "localhost:4714", "Transparent proxy target")
var mode = flag.String("mode", "transparent", "tor/transparent/TODO") // TODO

func debugPrintln(v ...interface{}) {
	if *debug {
		log.Println(v)
	}
}

func debugPrintf(format string, v ...interface{}) {
	if *debug {
		log.Printf(format, v)
	}
}

// Reads ClientHello from the connection.
// Returns addr, hello, http req, and error
func ReadInitiaWSRequest(clientConn net.Conn) (string, []byte, interface{}, error) {
	expectedH1Req := "GET /" + *secretLink
	log.SetPrefix(fmt.Sprintf("[%s] ", clientConn.RemoteAddr().String()))
	connReader := bufio.NewReader(clientConn)

	firstBytes, err := connReader.Peek(len(expectedH1Req))
	if err != nil {
		return "", nil, nil, err
	}

	if string(firstBytes) == expectedH1Req {
		req, err := http.ReadRequest(connReader)
		if err != nil {
			return "", nil, nil, err
		}

		if strings.ToLower(req.Header.Get("Connection")) != "upgrade" {
			return "", nil, nil, fmt.Errorf("Connection header expected: upgrade, got: %s\n",
				strings.ToLower(req.Header.Get("Connection")))
		}
		if strings.ToLower(req.Header.Get("Upgrade")) != "websocket" {
			return "", nil, nil, fmt.Errorf("Upgrade header expected: websocket, got: %s\n",
				strings.ToLower(req.Header.Get("Upgrade")))
		}

		clientHello, err := base64.StdEncoding.DecodeString(req.Header.Get("X-ReframerCH"))
		if err != nil {
			return "", nil, nil, err
		}
		targetAddr := req.Header.Get("X-TargetAddr")

		return targetAddr, clientHello, req, nil
	} else {
		// TODO: golang.org/x/net/http2 instead
		req, err := http.ReadRequest(connReader)
		if err != nil {
			log.Println(err)
			return "", nil, nil, err
		}
		reqBytes, err := httputil.DumpRequest(req, false)
		log.Println(string(reqBytes), err)
		return "", nil, nil, err
	}
}

func GenerateInitialWSResponse(hello []byte, _req interface{}) ([]byte, error) {
	req, ok := _req.(*http.Request)
	if !ok {
		panic(_req)
	}

	resp := http.Response{
		Status:           "101 Switching Protocols",
		StatusCode:       101,
		Proto:            "HTTP/1.1",
		ProtoMajor:       1,
		ProtoMinor:       1,
		Header:           http.Header{},
		Body:             nil,
		ContentLength:    0,
		TransferEncoding: nil,
		Close:            false,
		Uncompressed:     false,
		Trailer:          nil,
		Request:          nil,
		TLS:              nil,
	}
	resp.Header.Set("Upgrade", req.Header.Get("Upgrade"))
	resp.Header.Set("Connection", req.Header.Get("Connection"))
	if len(hello) > 0 {
		resp.Header.Set("X-ReframerSH", base64.StdEncoding.EncodeToString(hello))
	}

	log.Println("GenerateInitialWSResponse")
	return httputil.DumpResponse(&resp, true)
}

func handleConn(clientConn net.Conn) error {
	log.SetPrefix("["+ clientConn.LocalAddr().String() + "] ")
	defer func() {
		closeErr := clientConn.Close()
		if closeErr == nil {
			log.Println("Closed Connection")
		} else {
			log.Printf("Closed Connection with error: %v\n", closeErr)
		}
	}()

	targetAddr, clientHello, req, err := ReadInitiaWSRequest(clientConn)
	if err != nil {
		log.Println("error reading initial request", err)
		return err
	}

	serverConn, err := net.Dial("tcp", targetAddr)
	log.Println("connecting to ", targetAddr)
	if err != nil {
		log.Println("failed to connect to ", targetAddr, "error:", err)
		return err
	}

	resp, err := GenerateInitialWSResponse(nil, req)
	if err != nil {
		log.Println("error generating ws response", err)
		return err
	}

	_, err = clientConn.Write(resp)
	if err != nil {
		log.Println("error writing ws response", err)
		return err
	}

	_, err = serverConn.Write(clientHello)
	if err != nil {
		log.Println("error sending initial client request to the target:", err)
		return err
	}

	return httpt.TransparentProxy(clientConn, serverConn)
}

func main() {
	flag.Parse()

	if *debug {
		log.SetFlags(log.Lmicroseconds | log.Lshortfile)
	} else {
		log.SetFlags(log.Lmicroseconds | log.Ldate)
	}
	log.SetPrefix("[init] ")

	l, err := net.Listen("tcp", "127.0.0.1:5091")
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Started HTTPT server at %v\n", l.Addr().String())
	log.Printf("Secret Link is %v\n", *secretLink)
	// TODO: more info about config, exit etc here

	log.SetPrefix("[runtime] ")
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err)
			continue
		}
		go handleConn(conn)
	}
}