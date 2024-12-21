package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func forbiddenChecker(resp *http.Response, w http.ResponseWriter) error {
	if resp.StatusCode == 403 {
		w.WriteHeader(403)
		io.WriteString(w, "Forbidden 403\n")
		io.WriteString(w, "Maybe Youtube blocked the IP of this proxy?\n")
		return fmt.Errorf("%s returned %d", resp.Request.Host, resp.StatusCode)
	}
	return nil
}

func videoplayback(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()

	expire, err := strconv.ParseInt(q.Get("expire"), 10, 64)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, "Expire query string undefined")
		return
	}

	// Prevent the process of already expired playbacks
	// since they will return 403 from googlevideo server
	if (expire - time.Now().Unix()) <= 0 {
		w.WriteHeader(403)
		io.WriteString(w, "Videoplayback URL has expired.")
		return
	}

	c := q.Get("c")
	if c == "" {
		w.WriteHeader(400)
		io.WriteString(w, "'c' query string undefined.")
		return
	}

	host := q.Get("host")
	q.Del("host")

	if len(host) <= 0 {
		// Fallback to use mvi and mn to build a host
		mvi := q.Get("mvi")
		mn := strings.Split(q.Get("mn"), ",")

		if len(mvi) <= 0 {
			w.WriteHeader(400)
			io.WriteString(w, "'mvi' query string undefined")
			return
		}

		if len(mn) <= 0 {
			w.WriteHeader(400)
			io.WriteString(w, "'mn' query string undefined")
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

	// if c == "WEB" {
	// 	q.Set("alr", "yes")
	// }
	// if req.Header.Get("Range") != "" {
	// 	q.Set("range", req.Header.Get("Range"))
	// }

	path := req.URL.EscapedPath()

	proxyURL, err := url.Parse("https://" + host + path)
	if err != nil {
		log.Panic(err)
	}

	proxyURL.RawQuery = q.Encode()

	// https://github.com/FreeTubeApp/FreeTube/blob/5a4cd981cdf2c2a20ab68b001746658fd0c6484e/src/renderer/components/ft-shaka-video-player/ft-shaka-video-player.js#L1097
	body := []byte{0x78, 0} // protobuf body

	request, err := http.NewRequest("POST", proxyURL.String(), bytes.NewReader(body))
	if err != nil {
		log.Panic(err)
	}
	copyHeaders(req.Header, request.Header, false)

	switch c {
	case "ANDROID":
		request.Header.Set("User-Agent", "com.google.android.youtube/1537338816 (Linux; U; Android 13; en_US; ; Build/TQ2A.230505.002; Cronet/113.0.5672.24)")
	case "IOS":
		request.Header.Set("User-Agent", "com.google.ios.youtube/19.32.8 (iPhone14,5; U; CPU iOS 17_6 like Mac OS X;)")
	case "WEB":
		request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
	default:
		request.Header.Set("User-Agent", default_ua)
	}

	request.Header.Add("Origin", "https://www.youtube.com")
	request.Header.Add("Referer", "https://www.youtube.com/")

	resp, err := client.Do(request)
	if err != nil {
		log.Panic(err)
	}

	if resp.Header.Get("location") != "" {
		new_url, err := url.Parse(resp.Header.Get("location"))
		if err != nil {
			log.Panic(err)
		}
		request.URL = new_url
		resp, err = client.Do(request)
		if err != nil {
			log.Panic(err)
		}
	}

	if err := forbiddenChecker(resp, w); err != nil {
		atomic.AddInt64(&stats_.RequestsForbidden.Videoplayback, 1)
		metrics.RequestForbidden.Videoplayback.Inc()
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
	if err != nil {
		log.Panic(err)
	}

	request.Header.Set("User-Agent", default_ua)

	resp, err := client.Do(request)
	if err != nil {
		log.Panic(err)
	}

	if err := forbiddenChecker(resp, w); err != nil {
		atomic.AddInt64(&stats_.RequestsForbidden.Vi, 1)
		metrics.RequestForbidden.Vi.Inc()
		return
	}

	defer resp.Body.Close()

	// NoRewrite := strings.HasPrefix(resp.Header.Get("Content-Type"), "audio") || strings.HasPrefix(resp.Header.Get("Content-Type"), "video")
	// copyHeaders(resp.Header, w.Header(), NoRewrite)
	w.WriteHeader(resp.StatusCode)

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
	request.Header.Set("User-Agent", default_ua)
	if err != nil {
		log.Panic(err)
	}

	resp, err := client.Do(request)
	if err != nil {
		log.Panic(err)
	}

	if err := forbiddenChecker(resp, w); err != nil {
		atomic.AddInt64(&stats_.RequestsForbidden.Ggpht, 1)
		metrics.RequestForbidden.Ggpht.Inc()
		return
	}

	defer resp.Body.Close()

	NoRewrite := strings.HasPrefix(resp.Header.Get("Content-Type"), "audio") || strings.HasPrefix(resp.Header.Get("Content-Type"), "video")
	copyHeaders(resp.Header, w.Header(), NoRewrite)
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}
