package httpc

import (
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go/http3"
)

var Ipv6_only = false
var Proxy string
var Client *http.Client

var dialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

// QUIC doesn't seem to support HTTP nor SOCKS5 proxies due to how it's made.
// (Since it's UDP)
var H3client = &http.Client{
	Transport: &http3.Transport{},
	Timeout:   10 * time.Second,
}

// http/2 client
var H2client = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			var net string
			if Ipv6_only {
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
		Proxy: func(r *http.Request) (*url.URL, error) {
			if Proxy != "" {
				return url.Parse(Proxy)
			}
			return nil, nil
		},
	},
}
