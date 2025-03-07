package paths

import (
	"net/http"
	"regexp"
)

const (
	default_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
	ggpht_host = "yt3.ggpht.com"
)

var manifest_re = regexp.MustCompile(`(?m)URI="([^"]+)"`)

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

var videoplayback_headers = http.Header{
	"Accept":          {"*/*"},
	"Accept-Encoding": {"gzip, deflate, br, zstd"},
	"Accept-Language": {"en-us,en;q=0.5"},
	"Origin":          {"https://www.youtube.com"},
	"Referer":         {"https://www.youtube.com/"},
}
