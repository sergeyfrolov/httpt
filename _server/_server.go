// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"

	_ "./inithack"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/mholt/caddy"

	// imports below are to run init() and register the forwardproxy plugin, set default variables
	_ "github.com/caddyserver/forwardproxy"
	_ "github.com/mholt/caddy/caddy/caddymain"
)

// TODO: stop goroutine leaking in copyLoops

var ptInfo pt.ServerInfo

// When a connection handler starts, +1 is written to this channel; when it
// ends, -1 is written.
var handlerChan = make(chan int)

func copyLoop(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(b, a)
		wg.Done()
	}()
	go func() {
		io.Copy(a, b)
		wg.Done()
	}()
	wg.Wait()
}

// Parses Forwarded and X-Forwarded-For headers, and returns client's IP:port.
// According to RFC, hostnames and  addresses without port are valid, but Tor spec mandates IP:port,
// so those are currently return error.
// Returns "", nil if there are no headers indicating forwarding.
// Returns "", err if there are forwarding headers, but they are misformatted/don't contain IP:port
// Returns "IPAddr", nil on successful parse.
func parseForwardedTor(header http.Header) (string, error) {
	var ipAddr string
	proxyEvidence := false
	xFFHeader := header.Get("X-Forwarded-For")
	if xFFHeader != "" {
		proxyEvidence = true
		for _, ip := range strings.Split(xFFHeader, ",") {
			ipAddr = strings.Trim(ip, " \"")
			break
		}
	}
	forwardedHeader := header.Get("Forwarded")
	if forwardedHeader != "" {
		proxyEvidence = true
		for _, fValue := range strings.Split(forwardedHeader, ";") {
			s := strings.Split(fValue, "=")
			if len(s) != 2 {
				return "", errors.New("misformatted \"Forwarded:\" header")
			}
			if strings.ToLower(strings.Trim(s[0], " ")) == "for" {
				ipAddr = strings.Trim(s[1], " \"")
				break
			}
		}
	}
	if ipAddr == "" {
		if proxyEvidence == true {
			return "", errors.New("Forwarded or X-Forwarded-For header is present, but could not be parsed")
		}
		return "", nil
	}

	// According to https://github.com/torproject/torspec/blob/master/proposals/196-transport-control-ports.txt
	// there are 2 acceptable formats:
	//     1.2.3.4:5678
	//     [1:2::3:4]:5678 // (spec says [1:2::3:4]::5678 but that must be a typo)
	h, p, err := net.SplitHostPort(ipAddr)
	if err != nil {
		return "", err
	}
	if net.ParseIP(h) == nil {
		return "", errors.New(h + " is not a valid IP address")
	}
	return net.JoinHostPort(h, p), nil
}

func handler(conn net.Conn) error {
	defer conn.Close()

	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()
	var err error

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return err
	}

	clientIP, err := parseForwardedTor(req.Header)
	if err != nil {
		// just print the error to log. eventually, we may decide to reject connections,
		// if Forwarded/X-Forwarded-For header is present, but misformatted/misparsed
		log.Println(err)
	}
	if clientIP == "" {
		// if err != nil, conn.RemoteAddr() is certainly not the right IP
		// but testing showed that connection fails to establish if clientIP is empty
		clientIP = conn.RemoteAddr().String()
	}

	or, err := pt.DialOr(&ptInfo, clientIP, "httpsproxy")
	if err != nil {
		return err
	}
	defer or.Close()

	// TODO: consider adding support for HTTP/2, HAPROXY-style PROXY protocol, SOCKS, etc.
	_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		return err
	}

	copyLoop(conn, or)

	return nil
}

func acceptLoop(ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			return err
		}
		go handler(conn)
	}
}

var (
	torPtStateLocationEnvVar string // directory where PT is allowed to store things

	bridgeUrl url.URL // bridge URL to register with bridgeDB

	// cli args
	runCaddy                bool
	serverName              string
	keyPemPath, certPemPath string
	cliUrlPTstr             string
	logFile                 string
)

func parseValidateCliArgs() error {
	// flag package is global and arguments get inevitably mixed with those of Caddy
	// It's a bit messy, but allows us to easily pass arguments to Caddy
	// To cleanup, we would have to reimplement argument parsing (or use 3rd party flag package)
	flag.BoolVar(&runCaddy, "runcaddy", true, "Start Caddy web server on ports 443 and 80 (redirects to 443) together with the PT."+
		" You can disable this option, set static 'ServerTransportListenAddr httpsproxy 127.0.0.1:ptPort' in torrc,"+
		" spin up frontend manually, and forward client's CONNECT request to 127.0.0.1:ptPort.")
	flag.StringVar(&serverName, "servername", "", "Server Name used. Used as TLS SNI on the client side, and to start Caddy.")

	flag.StringVar(&keyPemPath, "key", "", "Path to TLS key. Requires --cert. If set, caddy will not get Lets Encrypt TLS certificate.")
	flag.StringVar(&certPemPath, "cert", "", "Path to TLS cert. Requires --key. If set, caddy will not get Lets Encrypt TLS certificate.")

	flag.StringVar(&cliUrlPTstr, "url", "", "Set/override access url in form of https://username:password@1.2.3.4:443/."+
		" If servername is set or cert argument has a certificate with correct domain name,"+
		" this arg is optional and will be inferred, username:password will be auto-generated and stored, if not provided.")

	flag.StringVar(&logFile, "logfile", path.Join(torPtStateLocationEnvVar, "caddy.log"),
		"Log file for Pluggable Transport.")
	flag.Parse()

	if (keyPemPath == "" && certPemPath != "") || (keyPemPath != "" && certPemPath == "") {
		return errors.New("--cert and --key options must be used together")
	}

	if runCaddy == true && (serverName == "" && keyPemPath == "" && cliUrlPTstr == "") {
		return errors.New("for automatic launch of Caddy web server(`runcaddy=true` by default)," +
			"please specify either --servername, --url, or --cert and --key")
	}

	var err error
	cliUrlPT := &url.URL{}
	if cliUrlPTstr != "" {
		cliUrlPT, err = url.Parse(cliUrlPTstr)
		if err != nil {
			return err
		}
	}

	var storedCredentials *url.Userinfo
	if cliUrlPT.User.Username() == "" && runCaddy == true {
		// if operator hasn't specified the credentials in url and requests to start caddy,
		// use credentials, stored to disk
		storedCredentials, err = readCredentialsFromConfig()
		if err != nil {
			quitWithSmethodError(err.Error())
		}
		err := saveCredentialsToConfig(storedCredentials)
		if err != nil {
			// if can't save credentials persistently, and they were NOT provided as cli, die
			quitWithSmethodError(
				fmt.Sprintf("failed to save auto-generated proxy credentials: %s."+
					"Fix the error or specify credentials in `url=` argument", err))
		}
	}

	bridgeUrl, err = generatePTUrl(*cliUrlPT, storedCredentials, &serverName)
	return err
}

func quitWithSmethodError(errStr string) {
	pt.SmethodError("httpsproxy", errStr)
	os.Exit(2)
}

var sigChan chan os.Signal

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic: %s\nstack trace: %s\n", r, debug.Stack())
			pt.ProxyError(fmt.Sprintf("panic: %v. (check PT log for detailed trace)", r))
		}
	}()

	torPtStateLocationEnvVar = os.Getenv("TOR_PT_STATE_LOCATION")
	if torPtStateLocationEnvVar == "" {
		quitWithSmethodError("Set torPtStateLocationEnvVar")
	}
	err := os.MkdirAll(torPtStateLocationEnvVar, 0700)
	if err != nil {
		quitWithSmethodError(fmt.Sprintf("Failed to open/create %s: %s", torPtStateLocationEnvVar, err))
	}

	if err := parseValidateCliArgs(); err != nil {
		quitWithSmethodError("failed to parse PT arguments: " + err.Error())
	}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0660)
		if err != nil {
			quitWithSmethodError(fmt.Sprintf("error opening file %s: %v", logFile, err))
		}
		defer f.Close()
		log.SetOutput(f)
		os.Stdout = f
		os.Stderr = f
	}

	ptInfo, err = pt.ServerSetup(nil)
	if err != nil {
		quitWithSmethodError(err.Error())
	}

	var ptAddr net.Addr
	if len(ptInfo.Bindaddrs) != 1 {
		// TODO: is it even useful to have multiple bindaddrs and how would we use them? We don't
		// want to accept direct connections to PT, as it doesn't use security protocols like TLS
		quitWithSmethodError("only one bind address is supported")
	}
	bindaddr := ptInfo.Bindaddrs[0]
	if bindaddr.MethodName != "httpsproxy" {
		quitWithSmethodError("no such method")
	}

	listener, err := net.ListenTCP("tcp", bindaddr.Addr)
	if err != nil {
		quitWithSmethodError(err.Error())
	}
	ptAddr = listener.Addr()
	colonIdx := strings.LastIndex(ptAddr.String(), ":")
	if colonIdx == -1 || len(ptAddr.String()) == colonIdx+1 {
		quitWithSmethodError("Bindaddr " + ptAddr.String() + " does not contain port")
	}
	ptAddrPort := ptAddr.String()[colonIdx+1:]

	go acceptLoop(listener)

	ptBridgeLineArgs := make(pt.Args)
	if serverName != "" {
		ptBridgeLineArgs["sni"] = []string{serverName}
	}

	var numHandlers int = 0
	var sig os.Signal

	sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	if runCaddy {
		startUsptreamingCaddy("http://localhost:"+ptAddrPort, ptBridgeLineArgs)
	}

	ptBridgeLineArgs["proxy"] = []string{bridgeUrl.String()}

	// print bridge line
	argsAsString := func(args *pt.Args) string {
		str := ""
		for k, v := range *args {
			str += k + "=" + strings.Join(v, ",") + " "
		}
		return strings.Trim(str, " ")
	}
	log.Printf("Bridge line: %s %s [fingerprint] %s\n",
		bindaddr.MethodName, listener.Addr(), argsAsString(&ptBridgeLineArgs))

	// register bridge line
	pt.SmethodArgs(bindaddr.MethodName, listener.Addr(), ptBridgeLineArgs)
	pt.SmethodsDone()

	if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
		// This environment variable means we should treat EOF on stdin
		// just like SIGTERM: https://bugs.torproject.org/15435.
		go func() {
			io.Copy(ioutil.Discard, os.Stdin)
			sigChan <- syscall.SIGTERM
		}()
	}

	// keep track of handlers and wait for a signal
	sig = nil
	for sig == nil {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
			log.Println("Got EOF on stdin, exiting")
		}
	}

	// signal received, shut down
	listener.Close()

	for numHandlers > 0 {
		numHandlers += <-handlerChan
	}
}

func generateRandomString(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	randByte := make([]byte, 1)

	var randStr string
	for i := 0; i < length; i++ {
		_, err := rand.Read(randByte)
		if err != nil {
			panic(err)
		}
		randStr += string(alphabet[int(randByte[0])%len(alphabet)])
	}
	return randStr
}

// Reads credentials from ${TOR_PT_STATE_LOCATION}/config.txt, initializes blank values
func readCredentialsFromConfig() (*url.Userinfo, error) {
	config, err := os.Open(path.Join(torPtStateLocationEnvVar, "config.txt"))
	if err != nil {
		config, err = os.Create(path.Join(torPtStateLocationEnvVar, "config.txt"))
		if err != nil {
			return nil, err
		}
	}
	defer config.Close()

	var ptConfig map[string]string
	ptConfig = make(map[string]string)
	scanner := bufio.NewScanner(config)
	for scanner.Scan() {
		trimmedLine := strings.Trim(scanner.Text(), " ")
		if trimmedLine == "" {
			continue
		}
		line := strings.SplitN(trimmedLine, "=", 2)
		if len(line) < 2 {
			return nil, errors.New("Config line does not have '=': " + scanner.Text())
		}
		ptConfig[strings.Trim(line[0], " ")] = strings.Trim(line[1], " ")
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if _, exists := ptConfig["username"]; !exists {
		ptConfig["username"] = generateRandomString(6)
	}
	if _, exists := ptConfig["password"]; !exists {
		ptConfig["password"] = generateRandomString(6)
	}

	return url.UserPassword(ptConfig["username"], ptConfig["password"]), nil
}

func saveCredentialsToConfig(creds *url.Userinfo) error {
	configStr := fmt.Sprintf("%s=%s\n", "username", creds.Username())
	pw, _ := creds.Password()
	configStr += fmt.Sprintf("%s=%s\n", "password", pw)

	return ioutil.WriteFile(path.Join(torPtStateLocationEnvVar, "config.txt"), []byte(configStr), 0700)
}

// generates full https://user:pass@host:port URL using 'url=' argument(if given),
// then fills potential blanks with stored credentials and given serverName
func generatePTUrl(cliUrlPT url.URL, configCreds *url.Userinfo, serverName *string) (url.URL, error) {
	ptUrl := cliUrlPT
	switch ptUrl.Scheme {
	case "":
		ptUrl.Scheme = "https"
	case "https":
	default:
		return ptUrl, errors.New("Unsupported scheme: " + ptUrl.Scheme)
	}

	useCredsFromConfig := false
	if ptUrl.User == nil {
		useCredsFromConfig = true
	} else {
		if _, pwExists := ptUrl.User.Password(); ptUrl.User.Username() == "" && !pwExists {
			useCredsFromConfig = true
		}
	}
	if useCredsFromConfig {
		ptUrl.User = configCreds
	}

	port := ptUrl.Port()
	if port == "" {
		port = "443"
	}

	hostname := ptUrl.Hostname() // first try hostname provided as cli arg, if any
	if hostname == "" {
		// then sni provided as cli arg
		hostname = *serverName
	}
	if hostname == "" {
		// lastly, try to get outbound IP by dialing https://diagnostic.opendns.com/myip
		const errStr = "Could not automatically determine external ip using https://diagnostic.opendns.com/myip: %s. " +
			"You can specify externally routable IP address in url="
		resp, err := http.Get("https://diagnostic.opendns.com/myip")
		if err != nil {
			return ptUrl, errors.New(fmt.Sprintf(errStr, err.Error()))
		}
		ipAddr, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return ptUrl, errors.New(fmt.Sprintf(errStr, err.Error()))
		}
		hostname = string(ipAddr)
		if net.ParseIP(hostname) == nil {
			return ptUrl, errors.New(fmt.Sprintf(errStr, "response: "+hostname))
		}
	}
	ptUrl.Host = net.JoinHostPort(hostname, port)

	return ptUrl, nil
}

// If successful, returns domain name, parsed from cert (could be empty) and SPKI fingerprint.
// On error will os.Exit()
func validateAndParsePem(keyPath, certPath *string) (string, []byte) {
	_, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		quitWithSmethodError("Could not read" + *keyPath + ": " + err.Error())
	}

	certBytes, err := ioutil.ReadFile(*certPath)
	if err != nil {
		quitWithSmethodError("failed to read" + *certPath + ": " + err.Error())
	}

	var pemBlock *pem.Block
	for {
		// find last block
		p, remainingCertBytes := pem.Decode([]byte(certBytes))
		if p == nil {
			break
		}
		certBytes = remainingCertBytes
		pemBlock = p
	}
	if pemBlock == nil {
		quitWithSmethodError("failed to parse any blocks from " + *certPath)
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		quitWithSmethodError("failed to parse certificate from last block of" +
			*certPath + ": " + err.Error())
	}

	cn := cert.Subject.CommonName
	if strings.HasSuffix(cn, "*.") {
		cn = cn[2:]
	}

	h := sha256.New()
	_, err = h.Write(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		quitWithSmethodError("cert hashing error" + err.Error())
	}
	spkiFP := h.Sum(nil)

	return cn, spkiFP
}

// non-blocking
func startUsptreamingCaddy(upstream string, ptBridgeLineArgs pt.Args) {
	if serverName == "" {
		quitWithSmethodError("Set `-caddyname` argument in ServerTransportPlugin")
	}

	caddyRoot := path.Join(torPtStateLocationEnvVar, "caddy_root")
	err := os.MkdirAll(caddyRoot, 0700)
	if err != nil {
		quitWithSmethodError(
			fmt.Sprintf("failed to read/create %s: %s\n", caddyRoot, err))
	}
	if _, err := os.Stat(path.Join(caddyRoot, "index.html")); os.IsNotExist(err) {
		log.Println("Please add/symlink web files (or at least index.html) to " + caddyRoot +
			" to look like an actual website and stop serving 404 on /")
	}

	extraDirectives := ""
	if keyPemPath != "" && certPemPath != "" {
		domainCN, spkiFp := validateAndParsePem(&keyPemPath, &certPemPath)
		// We could potentially generate certs from Golang, but there's way too much stuff in x509
		// For fingerprintability reasons, might be better to advise use of openssl
		serverName = domainCN
		if _, alreadySetUsingCliArg := ptBridgeLineArgs.Get("sni"); domainCN != "" && net.ParseIP(domainCN) == nil && !alreadySetUsingCliArg {
			ptBridgeLineArgs["sni"] = []string{domainCN}
		}

		// TODO: if cert is already trusted: do not set proxyspki
		ptBridgeLineArgs["proxyspki"] = []string{hex.EncodeToString(spkiFp)}

		extraDirectives += fmt.Sprintf("tls %s %s\n", certPemPath, keyPemPath)
	}

	caddyHostname := serverName
	if caddyHostname == "" {
		caddyHostname = bridgeUrl.Hostname()
	}
	caddyPw, _ := bridgeUrl.User.Password()
	caddyFile := fmt.Sprintf(`%s {
  forwardproxy {
    basicauth %s %s
    probe_resistance
    upstream %s
  }
  log / stdout "[{when}] \"{method} {uri} {proto}\" {status} {size}"
  errors stdout
  root %s
  %s
}
`, caddyHostname,
		bridgeUrl.User.Username(), caddyPw,
		upstream,
		caddyRoot,
		extraDirectives)

	caddyInstance, err := caddy.Start(caddy.CaddyfileInput{ServerTypeName: "http", Contents: []byte(caddyFile)})
	if err != nil {
		pt.ProxyError("failed to start caddy: " + err.Error())
		os.Exit(9)
	}
	go func() {
		caddyInstance.Wait() // if caddy stopped -- exit
		pt.ProxyError("Caddy has stopped. Exiting.")
		sigChan <- syscall.SIGTERM
	}()
}
