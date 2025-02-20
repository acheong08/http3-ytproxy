package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.nadeko.net/Fijxu/http3-ytproxy/internal/httpc"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/metrics"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/paths"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/utils"
	"github.com/conduitio/bwlimit"
	"github.com/prometheus/procfs"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var (
	wl = flag.Int("w", 8000, "Write limit in Kbps")
	rl = flag.Int("r", 8000, "Read limit in Kbps")
)

var h3s bool

var domain_only_access bool = false

var version string

type ConnectionWatcher struct {
	totalEstablished int64
	established      int64
	active           int64
	idle             int64
}

// https://stackoverflow.com/questions/51317122/how-to-get-number-of-idle-and-active-connections-in-go
// OnStateChange records open connections in response to connection
// state changes. Set net/http Server.ConnState to this method
// as value.
func (cw *ConnectionWatcher) OnStateChange(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		metrics.Metrics.EstablishedConnections.Inc()
		metrics.Metrics.TotalConnEstablished.Inc()
	// case http.StateActive:
	// 	atomic.AddInt64(&cw.active, 1)
	case http.StateClosed, http.StateHijacked:
		metrics.Metrics.EstablishedConnections.Dec()
	}
}

var cw ConnectionWatcher

var tx uint64

func blockCheckerCalc(p *procfs.Proc) {
	var last uint64
	for {
		time.Sleep(1 * time.Second)
		// p.NetDev should never fail.
		stat, _ := p.NetDev()
		current := stat.Total().TxBytes
		tx = current - last
		last = current
	}
}

// Detects if a backend has been blocked based on the amount of bandwidth
// reported by procfs.
// This may be the best way to detect if the IP has been blocked from googlevideo
// servers. I would like to detect blockages using the status code that googlevideo
// returns, which most of the time is 403 (Forbidden). But this error code is not
// exclusive to IP blocks, it's also returned for other reasons like a wrong
// query parameter like `pot` (po_token) or anything like that.
func blockChecker(gh string, cooldown int) {
	log.Println("[INFO] Starting blockchecker")
	// Sleep for 60 seconds before commencing the loop
	time.Sleep(60 * time.Second)
	url := "http://" + gh + "/v1/openvpn/status"

	p, err := procfs.Self()
	if err != nil {
		log.Printf("[ERROR] [procfs]: Could not get process: %s\n", err)
		log.Println("[INFO] Blockchecker will not run, so if the VPN IP used on gluetun gets blocked, it will not be rotated!")
		return
	}
	go blockCheckerCalc(&p)

	for {
		time.Sleep(time.Duration(cooldown) * time.Second)
		if float64(tx)*0.000008 < 2.0 {
			body := "{\"status\":\"stopped\"}\""
			// This should never fail too
			request, _ := http.NewRequest("PUT", url, strings.NewReader(body))
			_, err = httpc.Client.Do(request)
			if err != nil {
				log.Printf("[ERROR] Failed to send request to gluetun.")
			} else {
				log.Printf("[INFO] Request to change IP sent to gluetun successfully")
			}
		}
	}
}

func beforeMisc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		defer utils.PanicHandler(w)

		// To prevent accessing from the bare IP address
		if domain_only_access && (req.Host == "" || net.ParseIP(strings.Split(req.Host, ":")[0]) != nil) {
			w.WriteHeader(444)
			return
		}

		next(w, req)
	}
}

func beforeProxy(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		defer utils.PanicHandler(w)

		// To prevent accessing from the bare IP address
		if domain_only_access && (req.Host == "" || net.ParseIP(strings.Split(req.Host, ":")[0]) != nil) {
			w.WriteHeader(444)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Max-Age", "1728000")
		w.Header().Set("Strict-Transport-Security", "max-age=86400")
		w.Header().Set("X-Powered-By", "http3-ytproxy "+version+"-"+runtime.GOARCH)

		if h3s {
			w.Header().Set("Alt-Svc", "h3=\":8443\"; ma=86400")
		}

		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if req.Method != "GET" && req.Method != "HEAD" {
			w.WriteHeader(405)
			io.WriteString(w, "Only GET and HEAD requests are allowed.")
			return
		}

		metrics.Metrics.RequestCount.Inc()
		next(w, req)
	}
}

func main() {
	defaultHost := "0.0.0.0"
	defaultPort := "8080"
	defaultSock := "/tmp/http-ytproxy.sock"
	defaultTLSCert := "/data/cert.pem"
	defaultTLSKey := "/data/key.key"

	var https bool = false
	var h3c bool = false
	var ipv6 bool = false
	var bc bool = true

	if strings.ToLower(os.Getenv("HTTPS")) == "true" {
		https = true
	}
	if strings.ToLower(os.Getenv("H3C")) == "true" {
		h3c = true
	}
	if strings.ToLower(os.Getenv("H3S")) == "true" {
		h3s = true
	}
	if strings.ToLower(os.Getenv("IPV6_ONLY")) == "true" {
		ipv6 = true
	}
	if strings.ToLower(os.Getenv("BLOCK_CHECKER")) == "false" {
		bc = false
	}
	if strings.ToLower(os.Getenv("DOMAIN_ONLY_ACCESS")) == "true" {
		domain_only_access = true
	}

	tls_cert := os.Getenv("TLS_CERT")
	if tls_cert == "" {
		tls_cert = defaultTLSCert
	}
	tls_key := os.Getenv("TLS_KEY")
	if tls_key == "" {
		tls_key = defaultTLSKey
	}
	sock := os.Getenv("SOCK_PATH")
	if sock == "" {
		sock = defaultSock
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}
	host := os.Getenv("HOST")
	if host == "" {
		host = defaultHost
	}
	// gh is where the gluetun api is located
	gh := os.Getenv("GLUETUN_HOSTNAME")
	if gh == "" {
		gh = "127.0.0.1:8000"
	}
	bc_cooldown := os.Getenv("BLOCK_CHECKER_COOLDOWN")
	if bc_cooldown == "" {
		bc_cooldown = "60"
	}
	httpc.Proxy = os.Getenv("PROXY")

	flag.BoolVar(&https, "https", https, "Use built-in https server (recommended)")
	flag.BoolVar(&h3c, "h3c", h3c, "Use HTTP/3 for client requests (high CPU usage)")
	flag.BoolVar(&h3s, "h3s", h3s, "Use HTTP/3 for server requests, (requires HTTPS)")
	flag.BoolVar(&httpc.Ipv6_only, "ipv6_only", httpc.Ipv6_only, "Only use ipv6 for requests")
	flag.StringVar(&tls_cert, "tls-cert", tls_cert, "TLS Certificate path")
	flag.StringVar(&tls_key, "tls-key", tls_key, "TLS Certificate Key path")
	flag.StringVar(&sock, "s", sock, "Specify a socket name")
	flag.StringVar(&port, "p", port, "Specify a port number")
	flag.StringVar(&host, "l", host, "Specify a listen address")
	flag.Parse()
	httpc.Ipv6_only = ipv6

	if h3c {
		httpc.Client = httpc.H3client
	} else {
		httpc.Client = httpc.H2client
	}

	if https {
		if len(tls_cert) <= 0 {
			log.Fatal("tls-cert argument is missing, you need a TLS certificate for HTTPS")
		}

		if len(tls_key) <= 0 {
			log.Fatal("tls-key argument is missing, you need a TLS key for HTTPS")
		}
	}

	mux := http.NewServeMux()

	// MISC ROUTES
	mux.HandleFunc("/", beforeMisc(paths.Root))
	mux.HandleFunc("/health", beforeMisc(paths.Health))

	metrics.Register()

	mux.Handle("/metrics", paths.MetricsHandler())

	// PROXY ROUTES
	mux.HandleFunc("/videoplayback", beforeProxy(paths.Videoplayback))
	mux.HandleFunc("/vi/", beforeProxy(paths.Vi))
	mux.HandleFunc("/vi_webp/", beforeProxy(paths.Vi))
	mux.HandleFunc("/sb/", beforeProxy(paths.Vi))
	mux.HandleFunc("/ggpht/", beforeProxy(paths.Ggpht))
	mux.HandleFunc("/a/", beforeProxy(paths.Ggpht))
	mux.HandleFunc("/ytc/", beforeProxy(paths.Ggpht))

	if bc {
		num, err := strconv.Atoi(bc_cooldown)
		if err != nil {
			log.Fatalf("[FATAL] Error while setting BLOCK_CHECKER_COOLDOWN: %s", err)
		}
		go blockChecker(gh, num)
	}

	ln, err := net.Listen("tcp", host+":"+port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// 1Kbit = 125Bytes
	var (
		writeLimit = bwlimit.Byte(*wl) * bwlimit.Byte(125)
		readLimit  = bwlimit.Byte(*rl) * bwlimit.Byte(125)
	)

	ln = bwlimit.NewListener(ln, writeLimit, readLimit)
	// srvDialer := bwlimit.NewDialer(&net.Dialer{}, writeLimit, readLimit)

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 1 * time.Hour,
		ConnState:    cw.OnStateChange,
	}

	srvh3 := &http3.Server{
		Handler:         mux,
		EnableDatagrams: false, // https://quic.video/blog/never-use-datagrams/ (Read it)
		IdleTimeout:     120 * time.Second,
		TLSConfig:       http3.ConfigureTLSConfig(&tls.Config{}),
		QUICConfig: &quic.Config{
			// KeepAlivePeriod:       10 * time.Second,
			MaxIncomingStreams:    256, // I'm not sure if this is correct.
			MaxIncomingUniStreams: 256, // Same as above
		},
		Addr: host + ":" + port,
	}

	syscall.Unlink(sock)
	socket_listener, err := net.Listen("unix", sock)

	if err != nil {
		log.Println("Failed to bind to UDS, please check the socket name", err.Error())
	} else {
		defer socket_listener.Close()
		// To allow everyone to access the socket
		err = os.Chmod(sock, 0777)
		if err != nil {
			log.Println("Failed to set socket permissions to 777:", err.Error())
			return
		} else {
			log.Println("Setting socket permissions to 777")
		}

		go srv.Serve(socket_listener)
		log.Println("Unix socket listening at:", string(sock))

		if https {
			if _, err := os.Open(tls_cert); errors.Is(err, os.ErrNotExist) {
				log.Panicf("Certificate file does not exist at path '%s'", tls_cert)
			}

			if _, err := os.Open(tls_key); errors.Is(err, os.ErrNotExist) {
				log.Panicf("Key file does not exist at path '%s'", tls_key)
			}

			log.Println("Serving HTTPS at port", string(port)+"/tcp")
			go func() {
				if err := srv.ServeTLS(ln, tls_cert, tls_key); err != nil {
					log.Fatal("Failed to server HTTP/2", err.Error())
				}
			}()
			if h3s {
				log.Println("Serving HTTP/3 (HTTPS) via QUIC at port", string(port)+"/udp")
				go func() {
					if err := srvh3.ListenAndServeTLS(tls_cert, tls_key); err != nil {
						log.Fatal("Failed to serve HTTP/3:", err.Error())
					}
				}()
			}
			select {}
		} else {
			log.Println("Serving HTTP at port", string(port))
			if err := srv.Serve(ln); err != nil {
				log.Fatal(err)
			}
		}
	}
}
