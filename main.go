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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/conduitio/bwlimit"
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

type statusJson struct {
	Version           string `json:"version"`
	RequestCount      int64  `json:"requestCount"`
	RequestPerSecond  int64  `json:"requestPerSecond"`
	RequestPerMinute  int64  `json:"requestPerMinute"`
	RequestsForbidden struct {
		Videoplayback int64 `json:"videoplayback"`
		Vi            int64 `json:"vi"`
		Ggpht         int64 `json:"ggpht"`
	} `json:"requestsForbidden"`
}

var stats_ = statusJson{
	Version:          version + "-" + runtime.GOARCH,
	RequestCount:     0,
	RequestPerSecond: 0,
	RequestPerMinute: 0,
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

func root(w http.ResponseWriter, req *http.Request) {
	const msg = `
	HTTP youtube proxy for https://inv.nadeko.net
	https://git.nadeko.net/Fijxu/http3-ytproxy
	
	Routes: 
	/stats
	/health`
	io.WriteString(w, msg)
}

func stats(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

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
		last = current
	}
}

func requestPerMinute() {
	var last int64
	for {
		time.Sleep(60 * time.Second)
		current := stats_.RequestCount
		stats_.RequestPerMinute = current - last
		last = current
	}
}

func beforeAll(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		defer panicHandler(w)

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

	mux.HandleFunc("/", root)
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/stats", stats)

	mux.HandleFunc("/videoplayback", beforeAll(videoplayback))
	mux.HandleFunc("/vi/", beforeAll(vi))
	mux.HandleFunc("/vi_webp/", beforeAll(vi))
	mux.HandleFunc("/sb/", beforeAll(vi))
	mux.HandleFunc("/ggpht/", beforeAll(ggpht))
	mux.HandleFunc("/a/", beforeAll(ggpht))
	mux.HandleFunc("/ytc/", beforeAll(ggpht))

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
