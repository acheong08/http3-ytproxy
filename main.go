package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
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

// Same user agent as Invidious
var ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"

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
}

var path_prefix = ""

var manifest_re = regexp.MustCompile(`(?m)URI="([^"]+)"`)

var ipv6_only = false

var version string

var h3s bool

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
		if req.Host == "" || net.ParseIP(strings.Split(req.Host, ":")[0]) != nil {
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
		if req.Host == "" || net.ParseIP(strings.Split(req.Host, ":")[0]) != nil {
			w.WriteHeader(444)
			return
		}

		if h3s {
			w.Header().Set("Alt-Svc", "h3=\":8443\"; ma=86400")
		}

		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if req.Method != "GET" && req.Method != "HEAD" {
			io.WriteString(w, "Only GET and HEAD requests are allowed.")
			return
		}

		// To look like more like a browser
		req.Header.Add("Origin", "https://www.youtube.com")
		req.Header.Add("Referer", "https://www.youtube.com/")

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Max-Age", "1728000")

		atomic.AddInt64(&stats_.RequestCount, 1)
		metrics.RequestCount.Inc()
		next(w, req)
	}
}

func main() {
	var sock string
	var host string
	var port string

	var tls_cert string
	var tls_key string
	var ipv6 bool
	var https bool
	var h3c bool

	ua = os.Getenv("USER_AGENT")
	https = os.Getenv("HTTPS") == "1"
	h3c = os.Getenv("H3C") == "1"
	h3s = os.Getenv("H3S") == "1"
	ipv6 = os.Getenv("IPV6_ONLY") == "1"

	flag.BoolVar(&https, "https", false, "Use built-in https server (recommended)")
	flag.BoolVar(&h3s, "h3c", false, "Use HTTP/3 for client requests (high CPU usage)")
	flag.BoolVar(&h3s, "h3s", true, "Use HTTP/3 for server requests")
	flag.BoolVar(&ipv6_only, "ipv6_only", false, "Only use ipv6 for requests")
	flag.StringVar(&tls_cert, "tls-cert", "", "TLS Certificate path")
	flag.StringVar(&tls_key, "tls-key", "", "TLS Certificate Key path")
	flag.StringVar(&sock, "s", "/tmp/http-ytproxy.sock", "Specify a socket name")
	flag.StringVar(&port, "p", "8080", "Specify a port number")
	flag.StringVar(&host, "l", "0.0.0.0", "Specify a listen address")
	flag.Parse()

	if h3c {
		client = h3client
	} else {
		client = h2client
	}

	if https {
		if len(tls_cert) <= 0 {
			fmt.Println("tls-cert argument is missing, you need a TLS certificate for HTTPS")
			os.Exit(1)
		}

		if len(tls_key) <= 0 {
			fmt.Println("tls-key argument is missing, you need a TLS key for HTTPS")
			os.Exit(1)
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
		fmt.Println("Failed to bind to UDS, please check the socket name")
		fmt.Println(err.Error())
	} else {
		defer socket_listener.Close()
		// To allow everyone to access the socket
		err = os.Chmod(sock, 0777)
		if err != nil {
			fmt.Println("Error setting permissions:", err)
			return
		} else {
			fmt.Println("Setting socket permissions to 777")
		}

		go srv.Serve(socket_listener)
		fmt.Println("Unix socket listening at:", string(sock))

		if https {
			fmt.Println("Serving HTTPS at port", string(port))
			go func() {
				if err := srv.ServeTLS(ln, tls_cert, tls_key); err != nil {
					log.Fatal(err)
				}
			}()
			if h3s {
				fmt.Println("Serving HTTPS via QUIC at port", string(port))
				go func() {
					if err := srvh3.ListenAndServeTLS(tls_cert, tls_key); err != nil {
						log.Fatal(err)
					}
				}()
			}
			select {}
		} else {
			fmt.Println("Serving HTTP at port", string(port))
			if err := srv.Serve(ln); err != nil {
				log.Fatal(err)
			}
		}
	}
}
