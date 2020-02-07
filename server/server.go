package main

import (
	"bufio"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

func main() {
	secretLink := flag.String("secret-link", "secretLink", "TODO") // TODO
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lshortfile)

	expectedH1Req := "GET /" + *secretLink

	l, err := net.Listen("tcp", "127.0.0.1:5091")
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("starting httpt server at %v with secretlink=%v\n", l.Addr().String(), *secretLink)

	handleConn := func(conn net.Conn) error {
		log.Println("Handling connection from", conn.RemoteAddr())
		defer func() {
			log.Println("Closed connection from", conn.RemoteAddr(), "with closing error =", conn.Close())
		}()
		connReader := bufio.NewReader(conn)

		firstBytes, err := connReader.Peek(len(expectedH1Req))
		if err != nil {
			log.Println(err)
			return err
		}

		if string(firstBytes) == expectedH1Req {
			req, err := http.ReadRequest(connReader)
			if err != nil {
				log.Println(err)
				return err
			}

			// reframerID := req.Header.Get("X-Reframer-Id")

			if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" &&
				strings.ToLower(req.Header.Get("Connection")) == "upgrade" {
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

				err = resp.Write(conn)
				if err != nil {
					log.Println(err)
					return err
				}

				// Limitation: server cannot be the first to talk here, as Apache2 gets confused.
				buf := make([]byte, 1024)
				n, err := connReader.Read(buf)
				log.Println(string(buf[:n]), err)

				_, err = conn.Write([]byte("hi, I am PT server!"))
				if err != nil {
					log.Println(err)
					return err
				}

				return nil
			} else {
				req, err := httputil.DumpRequest(req, false)
				log.Println(string(req), err)
				return err
			}

		} else {
			// TODO: golang.org/x/net/http2 instead
			req, err := http.ReadRequest(connReader)
			if err != nil {
				log.Println(err)
				return err
			}
			reqBytes, err := httputil.DumpRequest(req, false)
			log.Println(string(reqBytes), err)
			return err
		}
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConn(conn)
	}
}
