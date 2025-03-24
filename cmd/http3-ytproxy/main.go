package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"git.nadeko.net/Fijxu/http3-ytproxy/internal/config"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/httpc"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/metrics"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/paths"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/utils"
	"github.com/prometheus/procfs"
)

type ConnectionWatcher struct {
	totalEstablished int64
	established      int64
	active           int64
	idle             int64
}

var version string
var cw ConnectionWatcher
var tx uint64

// https://stackoverflow.com/questions/51317122/how-to-get-number-of-idle-and-active-connections-in-go
// OnStateChange records open connections in response to connection
// state changes. Set net/http Server.ConnState to this method
// as value.
func (cw *ConnectionWatcher) OnStateChange(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		metrics.Metrics.EstablishedConnections.Inc()
		metrics.Metrics.TotalConnEstablished.Inc()
	case http.StateClosed, http.StateHijacked:
		metrics.Metrics.EstablishedConnections.Dec()
	}
}

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
		next(w, req)
	}
}

func beforeProxy(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		defer utils.PanicHandler(w)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Max-Age", "1728000")
		w.Header().Set("Strict-Transport-Security", "max-age=86400")
		w.Header().Set("X-Powered-By", "http3-ytproxy "+version+"-"+runtime.GOARCH)

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

func init() {
	config.LoadConfig()
}

func main() {
	flag.BoolVar(&config.Cfg.Enable_http, "http", config.Cfg.Enable_http, "Enable HTTP Server")
	flag.BoolVar(&config.Cfg.Uds, "uds", config.Cfg.Uds, "Enable UDS (Unix socket domain)")
	flag.IntVar(&config.Cfg.Http_client_ver, "http-client-ver", config.Cfg.Http_client_ver, "Specify the HTTP Version that is going to be used on the client, accepted values are '1', '2 'and '3'")
	flag.BoolVar(&config.Cfg.Ipv6_only, "ipv6-only", config.Cfg.Ipv6_only, "Only use ipv6 for requests")
	flag.StringVar(&config.Cfg.Uds_path, "s", config.Cfg.Uds_path, "Specify the UDS (Unix socket domain) path\nExample: /run/http3-ytproxy.sock")
	flag.StringVar(&config.Cfg.Proxy, "pr", config.Cfg.Proxy, "Specify the proxy that is going to be used for requests\nExample: http://127.0.0.1:8090")
	flag.StringVar(&config.Cfg.Port, "p", config.Cfg.Port, "Specify a port number")
	flag.StringVar(&config.Cfg.Host, "l", config.Cfg.Host, "Specify a listen address")
	flag.Parse()

	switch config.Cfg.Http_client_ver {
	case 1:
		log.Println("[INFO] Using HTTP/1.1 Client")
		httpc.Client = httpc.H1_1client
	case 2:
		log.Println("[INFO] Using HTTP/2 Client")
		httpc.Client = httpc.H2client
	case 3:
		log.Println("[INFO] Using HTTP/3 Client")
		httpc.Client = httpc.H3client
	default:
		log.Println("[INFO] Using HTTP/1.1 Client")
		httpc.Client = httpc.H1_1client
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

	if config.Cfg.Gluetun.Block_checker {
		go blockChecker(config.Cfg.Gluetun.Gluetun_api, config.Cfg.Gluetun.Block_checker_cooldown)
	}

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 1 * time.Hour,
		ConnState:    cw.OnStateChange,
		Addr:         config.Cfg.Host + ":" + config.Cfg.Port,
	}

	if config.Cfg.Uds {
		syscall.Unlink(config.Cfg.Uds_path)
		socket_listener, err := net.Listen("unix", config.Cfg.Uds_path)
		if err != nil {
			log.Println("[ERROR] Failed to bind to UDS, please check the socket path", err.Error())
		}
		defer socket_listener.Close()
		err = os.Chmod(config.Cfg.Uds_path, 0777)
		if err != nil {
			log.Println("[ERROR] Failed to set socket permissions to 777:", err.Error())
			return
		} else {
			log.Println("[INFO] Setting socket permissions to 777")
		}

		go func() {
			err := srv.Serve(socket_listener)
			if err != nil {
				log.Println("[ERROR] Failed to listen serve UDS:", err)
			}
		}()

		// To allow everyone to access the socket
		log.Println("[INFO] Unix socket listening at:", config.Cfg.Uds_path)
	}

	if config.Cfg.Enable_http {
		log.Println("[INFO] Serving HTTP server at port", config.Cfg.Port)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("[FATAL] Failed to listen on '%s:%s': %s\n", config.Cfg.Host, config.Cfg.Port, err)
		}
	}
}
