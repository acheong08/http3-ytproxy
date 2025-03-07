package utils

const (
	path_prefix = ""
)

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

var headers_for_response = []string{
	"Content-Length",
	"Accept-Ranges",
	"Content-Type",
	"Expires",
	"Last-Modified",
}
