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

func Vi(w http.ResponseWriter, req *http.Request) {
	const host string = "i.ytimg.com"
	q := req.URL.Query()

	path := req.URL.EscapedPath()

	proxyURL, err := url.Parse("https://" + host + path)
	if err != nil {
		log.Panic(err)
	}

	if strings.HasSuffix(proxyURL.EscapedPath(), "maxres.jpg") {
		proxyURL.Path = utils.GetBestThumbnail(proxyURL.EscapedPath())
	}

	/*
		Required for /sb/ endpoints
		You can't access https://i.ytimg.com/sb/<VIDEOID>/storyboard3_L2/M3.jpg
		without it's parameters `sqp` and `sigh`
	*/
	proxyURL.RawQuery = q.Encode()

	request, err := http.NewRequest(req.Method, proxyURL.String(), nil)
	if err != nil {
		log.Panic(err)
	}

	request.Header.Set("User-Agent", default_ua)

	resp, err := httpc.Client.Do(request)
	if err != nil {
		log.Panic(err)
	}

	if err := forbiddenChecker(resp, w); err != nil {
		metrics.Metrics.RequestForbidden.Vi.Inc()
		return
	}

	defer resp.Body.Close()

	// NoRewrite := strings.HasPrefix(resp.Header.Get("Content-Type"), "audio") || strings.HasPrefix(resp.Header.Get("Content-Type"), "video")
	// copyHeaders(resp.Header, w.Header(), NoRewrite)
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}
