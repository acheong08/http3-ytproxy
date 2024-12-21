package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/conduitio/bwlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var (
	wl = flag.Int("w", 8000, "Write limit in Kbps")
	rl = flag.Int("r", 8000, "Read limit in Kbps")
)

var h3client = &http.Client{
	Transport: &http3.Transport{},
	Timeout:   10 * time.Second,
}

var dialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

// http/2 client
var h2client = &http.Client{
	Transport: &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			var net string
			if ipv6_only {
				net = "tcp6"
			} else {
				net = "tcp4"
			}
			return dialer.Dial(net, addr)
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		ReadBufferSize:        16 * 1024,
		ForceAttemptHTTP2:     true,
		MaxConnsPerHost:       0,
		MaxIdleConnsPerHost:   10,
		MaxIdleConns:          0,
	},
}

var client *http.Client

var default_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

var allowed_hosts = []string{
	"youtube.com",
	"googlevideo.com",
	"ytimg.com",
	"ggpht.com",
	"googleusercontent.com",
}

var strip_headers = []string{
	"Accept-Encoding",
	"Authorization",
	"Origin",
	"Referer",
	"Cookie",
	"Set-Cookie",
	"Etag",
	"Alt-Svc",
	"Server",
	"Cache-Control",
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to
	"report-to",
}

var path_prefix = ""

var manifest_re = regexp.MustCompile(`(?m)URI="([^"]+)"`)

var ipv6_only = false

var version string

var h3s bool

var domain_only_access bool = false

var programInit = time.Now()

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
		atomic.AddInt64(&stats_.EstablishedConnections, 1)
		metrics.EstablishedConnections.Inc()
		atomic.AddInt64(&stats_.TotalConnEstablished, 1)
		metrics.TotalConnEstablished.Inc()
	// case http.StateActive:
	// 	atomic.AddInt64(&cw.active, 1)
	case http.StateClosed, http.StateHijacked:
		atomic.AddInt64(&stats_.EstablishedConnections, -1)
		metrics.EstablishedConnections.Dec()
	}
}

// // Count returns the number of connections at the time
// // the call.
// func (cw *ConnectionWatcher) Count() int {
// 	return int(atomic.LoadInt64(&cw.n))
// }

// // Add adds c to the number of active connections.
// func (cw *ConnectionWatcher) Add(c int64) {
// 	atomic.AddInt64(&cw.n, c)
// }

var cw ConnectionWatcher

type statusJson struct {
	Version                string        `json:"version"`
	Uptime                 time.Duration `json:"uptime"`
	RequestCount           int64         `json:"requestCount"`
	RequestPerSecond       int64         `json:"requestPerSecond"`
	RequestPerMinute       int64         `json:"requestPerMinute"`
	TotalConnEstablished   int64         `json:"totalEstablished"`
	EstablishedConnections int64         `json:"establishedConnections"`
	ActiveConnections      int64         `json:"activeConnections"`
	IdleConnections        int64         `json:"idleConnections"`
	RequestsForbidden      struct {
		Videoplayback int64 `json:"videoplayback"`
		Vi            int64 `json:"vi"`
		Ggpht         int64 `json:"ggpht"`
	} `json:"requestsForbidden"`
}

var stats_ = statusJson{
	Version:                version + "-" + runtime.GOARCH,
	Uptime:                 0,
	RequestCount:           0,
	RequestPerSecond:       0,
	RequestPerMinute:       0,
	TotalConnEstablished:   0,
	EstablishedConnections: 0,
	ActiveConnections:      0,
	IdleConnections:        0,
	RequestsForbidden: struct {
		Videoplayback int64 `json:"videoplayback"`
		Vi            int64 `json:"vi"`
		Ggpht         int64 `json:"ggpht"`
	}{
		Videoplayback: 0,
		Vi:            0,
		Ggpht:         0,
	},
}

type Metrics struct {
	Uptime                 prometheus.Gauge
	RequestCount           prometheus.Counter
	RequestPerSecond       prometheus.Gauge
	RequestPerMinute       prometheus.Gauge
	TotalConnEstablished   prometheus.Counter
	EstablishedConnections prometheus.Gauge
	ActiveConnections      prometheus.Gauge
	IdleConnections        prometheus.Gauge
	RequestForbidden       struct {
		Videoplayback prometheus.Counter
		Vi            prometheus.Counter
		Ggpht         prometheus.Counter
	}
}

var metrics = Metrics{
	Uptime: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http3_ytproxy_uptime",
	}),
	RequestCount: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http3_ytproxy_request_count",
	}),
	RequestPerSecond: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http3_ytproxy_request_per_second",
	}),
	RequestPerMinute: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http3_ytproxy_request_per_minute",
	}),
	TotalConnEstablished: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http3_ytproxy_total_conn_established",
	}),
	EstablishedConnections: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http3_ytproxy_established_conns",
	}),
	ActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http3_ytproxy_active_conns",
	}),
	IdleConnections: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http3_ytproxy_idle_conns",
	}),

	RequestForbidden: struct {
		Videoplayback prometheus.Counter
		Vi            prometheus.Counter
		Ggpht         prometheus.Counter
	}{
		Videoplayback: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "http3_ytproxy_request_forbidden_videoplayback",
		}),
		Vi: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "http3_ytproxy_request_forbidden_vi",
		}),
		Ggpht: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "http3_ytproxy_request_forbidden_ggpht",
		}),
	},
}

func root(w http.ResponseWriter, req *http.Request) {
	const msg = `
	HTTP youtube proxy for https://inv.nadeko.net
	https://git.nadeko.net/Fijxu/http3-ytproxy

	Routes:
	/stats
	/health`
	io.WriteString(w, msg)
}

// CustomHandler wraps the default promhttp.Handler with custom logic
func metricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// To prevent accessing from the bare IP address
		if req.Host == "" || net.ParseIP(strings.Split(req.Host, ":")[0]) != nil {
			w.WriteHeader(444)
			return
		}

		metrics.Uptime.Set(float64(time.Duration(time.Since(programInit).Seconds())))
		promhttp.Handler().ServeHTTP(w, req)
	})
}

func stats(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats_.Uptime = time.Duration(time.Since(programInit).Seconds())
	// stats_.TotalEstablished = int64(cw.totalEstablished)
	// stats_.EstablishedConnections = int64(cw.established)
	// stats_.ActiveConnections = int64(cw.active)
	// stats_.IdleConnections = int64(cw.idle)

	if err := json.NewEncoder(w).Encode(stats_); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func health(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)
	io.WriteString(w, "OK")
}

func requestPerSecond() {
	var last int64
	for {
		time.Sleep(1 * time.Second)
		current := stats_.RequestCount
		stats_.RequestPerSecond = current - last
		metrics.RequestPerSecond.Set(float64(stats_.RequestPerSecond))
		last = current
	}
}

func requestPerMinute() {
	var last int64
	for {
		time.Sleep(60 * time.Second)
		current := stats_.RequestCount
		stats_.RequestPerMinute = current - last
		metrics.RequestPerMinute.Set(float64(stats_.RequestPerMinute))
		last = current
	}
}

func beforeMisc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		defer panicHandler(w)

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
		defer panicHandler(w)

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

		atomic.AddInt64(&stats_.RequestCount, 1)
		metrics.RequestCount.Inc()
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

	flag.BoolVar(&https, "https", https, "Use built-in https server (recommended)")
	flag.BoolVar(&h3c, "h3c", h3c, "Use HTTP/3 for client requests (high CPU usage)")
	flag.BoolVar(&h3s, "h3s", h3s, "Use HTTP/3 for server requests, (requires HTTPS)")
	flag.BoolVar(&ipv6_only, "ipv6_only", ipv6_only, "Only use ipv6 for requests")
	flag.StringVar(&tls_cert, "tls-cert", tls_cert, "TLS Certificate path")
	flag.StringVar(&tls_key, "tls-key", tls_key, "TLS Certificate Key path")
	flag.StringVar(&sock, "s", sock, "Specify a socket name")
	flag.StringVar(&port, "p", port, "Specify a port number")
	flag.StringVar(&host, "l", host, "Specify a listen address")
	flag.Parse()

	if h3c {
		client = h3client
	} else {
		client = h2client
	}

	if https {
		if len(tls_cert) <= 0 {
			log.Fatal("tls-cert argument is missing, you need a TLS certificate for HTTPS")
		}

		if len(tls_key) <= 0 {
			log.Fatal("tls-key argument is missing, you need a TLS key for HTTPS")
		}
	}

	ipv6_only = ipv6

	mux := http.NewServeMux()

	// MISC ROUTES
	mux.HandleFunc("/", beforeMisc(root))
	mux.HandleFunc("/health", beforeMisc(health))
	mux.HandleFunc("/stats", beforeMisc(stats))

	prometheus.MustRegister(metrics.Uptime)
	prometheus.MustRegister(metrics.ActiveConnections)
	prometheus.MustRegister(metrics.IdleConnections)
	prometheus.MustRegister(metrics.EstablishedConnections)
	prometheus.MustRegister(metrics.TotalConnEstablished)
	prometheus.MustRegister(metrics.RequestCount)
	prometheus.MustRegister(metrics.RequestPerSecond)
	prometheus.MustRegister(metrics.RequestPerMinute)
	prometheus.MustRegister(metrics.RequestForbidden.Videoplayback)
	prometheus.MustRegister(metrics.RequestForbidden.Vi)
	prometheus.MustRegister(metrics.RequestForbidden.Ggpht)

	mux.Handle("/metrics", metricsHandler())

	// PROXY ROUTES
	mux.HandleFunc("/videoplayback", beforeProxy(videoplayback))
	mux.HandleFunc("/vi/", beforeProxy(vi))
	mux.HandleFunc("/vi_webp/", beforeProxy(vi))
	mux.HandleFunc("/sb/", beforeProxy(vi))
	mux.HandleFunc("/ggpht/", beforeProxy(ggpht))
	mux.HandleFunc("/a/", beforeProxy(ggpht))
	mux.HandleFunc("/ytc/", beforeProxy(ggpht))

	go requestPerSecond()
	go requestPerMinute()

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
