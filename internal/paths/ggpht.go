package paths

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"git.nadeko.net/Fijxu/http3-ytproxy/internal/httpc"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/metrics"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/utils"
)

func Ggpht(w http.ResponseWriter, req *http.Request) {
	path := req.URL.EscapedPath()
	path = strings.Replace(path, "/ggpht", "", 1)
	path = strings.Replace(path, "/i/", "/", 1)

	proxyURL, err := url.Parse("https://" + ggpht_host + path)
	if err != nil {
		log.Panic(err)
	}

	request, err := http.NewRequest(req.Method, proxyURL.String(), nil)
	utils.CopyHeaders(req.Header, request.Header, false)
	request.Header.Set("User-Agent", default_ua)
	if err != nil {
		log.Panic(err)
	}

	resp, err := httpc.Client.Do(request)
	if err != nil {
		log.Panic(err)
	}

	if err := forbiddenChecker(resp, w); err != nil {
		metrics.Metrics.RequestForbidden.Ggpht.Inc()
		return
	}

	defer resp.Body.Close()

	NoRewrite := strings.HasPrefix(resp.Header.Get("Content-Type"), "audio") || strings.HasPrefix(resp.Header.Get("Content-Type"), "video")
	utils.CopyHeaders(resp.Header, w.Header(), NoRewrite)
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}
