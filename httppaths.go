package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func videoplayback(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	expire, err := strconv.ParseInt(q.Get("expire"), 10, 64)
	if err != nil {
		w.WriteHeader(500)
	}

	// Prevent the process of already expired playbacks
	// since they will return 403 from googlevideo servers.
	if (expire - time.Now().Unix()) <= 0 {
		w.WriteHeader(403)
		return
	}

	host := q.Get("host")
	q.Del("host")

	if len(host) <= 0 {
		mvi := q.Get("mvi")
		mn := strings.Split(q.Get("mn"), ",")

		if len(mvi) <= 0 {
			w.WriteHeader(400)
			io.WriteString(w, "No `mvi` in query parameters")
			return
		}

		if len(mn) <= 0 {
			w.WriteHeader(400)
			io.WriteString(w, "No `mn` in query parameters")
			return
		}

		host = "rr" + mvi + "---" + mn[0] + ".googlevideo.com"
	}

	parts := strings.Split(strings.ToLower(host), ".")

	if len(parts) < 2 {
		w.WriteHeader(400)
		io.WriteString(w, "Invalid hostname.")
		return
	}

	domain := parts[len(parts)-2] + "." + parts[len(parts)-1]
	disallowed := true
	for _, value := range allowed_hosts {
		if domain == value {
			disallowed = false
			break
		}
	}

	if disallowed {
		w.WriteHeader(401)
		io.WriteString(w, "Non YouTube domains are not supported.")
		return
	}

	path := req.URL.EscapedPath()

	proxyURL, err := url.Parse("https://" + host + path)
	if err != nil {
		log.Panic(err)
	}

	proxyURL.RawQuery = q.Encode()

	// https://github.com/FreeTubeApp/FreeTube/blob/5a4cd981cdf2c2a20ab68b001746658fd0c6484e/src/renderer/components/ft-shaka-video-player/ft-shaka-video-player.js#L1097
	body := []byte{0x78, 0} // protobuf body

	request, err := http.NewRequest("POST", proxyURL.String(), bytes.NewReader(body))
	copyHeaders(req.Header, request.Header, false)
	request.Header.Set("User-Agent", ua)
	if err != nil {
		log.Panic(err)
	}

	resp, err := client.Do(request)
	if err != nil {
		log.Panic(err)
	}

	if resp.StatusCode == 403 {
		atomic.AddInt64(&stats_.RequestsForbidden.Videoplayback, 1)
		metrics.RequestForbidden.Videoplayback.Inc()
		io.WriteString(w, "Forbidden 403\n")
		io.WriteString(w, "Maybe Youtube blocked the IP of this proxy?\n")
		return
	}

	defer resp.Body.Close()

	NoRewrite := strings.HasPrefix(resp.Header.Get("Content-Type"), "audio") || strings.HasPrefix(resp.Header.Get("Content-Type"), "video")
	copyHeaders(resp.Header, w.Header(), NoRewrite)

	w.WriteHeader(resp.StatusCode)

	if req.Method == "GET" && (resp.Header.Get("Content-Type") == "application/x-mpegurl" || resp.Header.Get("Content-Type") == "application/vnd.apple.mpegurl") {
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Panic(err)
		}

		lines := strings.Split(string(bytes), "\n")
		reqUrl := resp.Request.URL
		for i := 0; i < len(lines); i++ {
			line := lines[i]
			if !strings.HasPrefix(line, "https://") && (strings.HasSuffix(line, ".m3u8") || strings.HasSuffix(line, ".ts")) {
				path := reqUrl.EscapedPath()
				path = path[0 : strings.LastIndex(path, "/")+1]
				line = "https://" + reqUrl.Hostname() + path + line
			}
			if strings.HasPrefix(line, "https://") {
				lines[i] = RelativeUrl(line)
			}

			if manifest_re.MatchString(line) {
				url := manifest_re.FindStringSubmatch(line)[1]
				lines[i] = strings.Replace(line, url, RelativeUrl(url), 1)
			}
		}

		io.WriteString(w, strings.Join(lines, "\n"))
	} else {
		io.Copy(w, resp.Body)
	}
}

func vi(w http.ResponseWriter, req *http.Request) {
	const host string = "i.ytimg.com"
	q := req.URL.Query()

	path := req.URL.EscapedPath()

	proxyURL, err := url.Parse("https://" + host + path)
	if err != nil {
		log.Panic(err)
	}

	if strings.HasSuffix(proxyURL.EscapedPath(), "maxres.jpg") {
		proxyURL.Path = getBestThumbnail(proxyURL.EscapedPath())
	}

	/*
		Required for /sb/ endpoints
		You can't access https://i.ytimg.com/sb/<VIDEOID>/storyboard3_L2/M3.jpg
		without it's parameters `sqp` and `sigh`
	*/
	proxyURL.RawQuery = q.Encode()

	request, err := http.NewRequest(req.Method, proxyURL.String(), nil)

	copyHeaders(req.Header, request.Header, false)
	request.Header.Set("User-Agent", ua)
	if err != nil {
		log.Panic(err)
	}

	resp, err := client.Do(request)
	if err != nil {
		log.Panic(err)
	}

	w.WriteHeader(resp.StatusCode)
	if resp.StatusCode == 403 {
		atomic.AddInt64(&stats_.RequestsForbidden.Vi, 1)
		metrics.RequestForbidden.Vi.Inc()
		io.WriteString(w, "Forbidden 403")
		return
	}

	defer resp.Body.Close()

	NoRewrite := strings.HasPrefix(resp.Header.Get("Content-Type"), "audio") || strings.HasPrefix(resp.Header.Get("Content-Type"), "video")
	copyHeaders(resp.Header, w.Header(), NoRewrite)

	io.Copy(w, resp.Body)
}

func ggpht(w http.ResponseWriter, req *http.Request) {
	const host string = "yt3.ggpht.com"

	path := req.URL.EscapedPath()
	path = strings.Replace(path, "/ggpht", "", 1)
	path = strings.Replace(path, "/i/", "/", 1)

	proxyURL, err := url.Parse("https://" + host + path)
	if err != nil {
		log.Panic(err)
	}

	request, err := http.NewRequest(req.Method, proxyURL.String(), nil)
	copyHeaders(req.Header, request.Header, false)
	request.Header.Set("User-Agent", ua)
	if err != nil {
		log.Panic(err)
	}

	resp, err := client.Do(request)
	if err != nil {
		log.Panic(err)
	}

	w.WriteHeader(resp.StatusCode)
	if resp.StatusCode == 403 {
		atomic.AddInt64(&stats_.RequestsForbidden.Ggpht, 1)
		metrics.RequestForbidden.Ggpht.Inc()
		io.WriteString(w, "Forbidden 403")
		return
	}

	defer resp.Body.Close()

	NoRewrite := strings.HasPrefix(resp.Header.Get("Content-Type"), "audio") || strings.HasPrefix(resp.Header.Get("Content-Type"), "video")
	copyHeaders(resp.Header, w.Header(), NoRewrite)

	io.Copy(w, resp.Body)
}
