package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// http/3 client
var h3client = &http.Client{
	Transport: &http3.RoundTripper{},
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

// https://github.com/lucas-clemente/quic-go/issues/2836
var client = h2client

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

var reqs int64
var reqs_Forbidden int64
var mu sync.Mutex

type statusJson struct {
	RequestCount      int64 `json:"requestCount"`
	RequestsForbidden int64 `json:"requestsForbidden"`
}

func root(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, "HTTP youtube proxy for https://inv.nadeko.net\n")
}

func status(w http.ResponseWriter, req *http.Request) {
	response := statusJson{
		RequestCount:      reqs,
		RequestsForbidden: reqs_Forbidden,
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	var sock string
	var host string
	var port string
	var cert string
	var key string

	path_prefix = os.Getenv("PREFIX_PATH")

	ipv6_only = os.Getenv("IPV6_ONLY") == "1"
	// disable_webp = os.Getenv("DISABLE_WEBP") == "1"

	flag.StringVar(&cert, "tls-cert", "", "TLS Certificate path")
	flag.StringVar(&key, "tls-key", "", "TLS Certificate Key path")
	var https = flag.Bool("https", false, "Use built-in https server")
	var ipv6 = flag.Bool("ipv6_only", false, "Only use ipv6 for requests")
	flag.StringVar(&sock, "s", "/tmp/http-ytproxy.sock", "Specify a socket name")
	flag.StringVar(&port, "p", "8080", "Specify a port number")
	flag.StringVar(&host, "l", "0.0.0.0", "Specify a listen address")
	flag.Parse()

	ipv6_only = *ipv6

	mux := http.NewServeMux()

	mux.HandleFunc("/", root)
	mux.HandleFunc("/status", status)
	mux.HandleFunc("/videoplayback", videoplayback)
	mux.HandleFunc("/vi/", vi)
	mux.HandleFunc("/vi_webp/", vi)
	mux.HandleFunc("/sb/", vi)
	mux.HandleFunc("/ggpht/", ggpht)
	mux.HandleFunc("/a/", ggpht)
	mux.HandleFunc("/ytc/", ggpht)

	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 1 * time.Hour,
		Addr:         string(host) + ":" + string(port),
		Handler:      mux,
	}

	socket := string(sock)
	syscall.Unlink(socket)
	listener, err := net.Listen("unix", socket)
	fmt.Println("Unix socket listening at:", string(sock))

	if err != nil {
		fmt.Println("Failed to bind to UDS, please check the socket name, falling back to TCP/IP")
		fmt.Println(err.Error())
		err := srv.ListenAndServe()
		if err != nil {
			fmt.Println("Cannot bind to port", string(port), "Error:", err)
			fmt.Println("Please try changing the port number")
		}
	} else {
		defer listener.Close()
		// To allow everyone to access the socket
		err = os.Chmod(socket, 0777)
		if err != nil {
			fmt.Println("Error setting permissions:", err)
			return
		} else {
			fmt.Println("Setting socket permissions to 777")
		}
		go srv.Serve(listener)
		if *https {
			fmt.Println("Serving HTTPS at port", string(port))
			if err := srv.ListenAndServeTLS(cert, key); err != nil {
				log.Fatal(err)
			}
		} else {
			fmt.Println("Serving HTTP at port", string(port))
			srv.ListenAndServe()
		}
	}
}
