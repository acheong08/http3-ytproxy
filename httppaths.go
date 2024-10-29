package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func videoplayback(w http.ResponseWriter, req *http.Request) {
	mu.Lock()
	reqs++
	mu.Unlock()

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Max-Age", "1728000")

	if req.Method == "OPTIONS" {
		w.WriteHeader(200)
		return
	}

	q := req.URL.Query()

	mvi := q.Get("mvi")
	mn := strings.Split(q.Get("mn"), ",")

	if len(mvi) <= 0 {
		io.WriteString(w, "No `mvi` in query parameters")
		return
	}

	if len(mn) <= 0 {
		io.WriteString(w, "No `mn` in query parameters")
		return
	}

	host := "rr" + mvi + "---" + mn[0] + ".googlevideo.com"

	parts := strings.Split(strings.ToLower(host), ".")

	if len(parts) < 2 {
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
		io.WriteString(w, "Non YouTube domains are not supported.")
		return
	}

	if req.Method != "GET" && req.Method != "HEAD" {
		io.WriteString(w, "Only GET and HEAD requests are allowed.")
		return
	}

	path := req.URL.EscapedPath()

	proxyURL, err := url.Parse("https://" + host + path)
	if err != nil {
		log.Panic(err)
	}

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
	mu.Lock()
	reqs++
	mu.Unlock()

	const host string = "i.ytimg.com"
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Max-Age", "1728000")

	if req.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}

	parts := strings.Split(strings.ToLower(host), ".")
	if len(parts) < 2 {
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
		io.WriteString(w, "Non YouTube domains are not supported.")
		return
	}

	if req.Method != "GET" && req.Method != "HEAD" {
		io.WriteString(w, "Only GET and HEAD requests are allowed.")
		return
	}

	path := req.URL.EscapedPath()
	fmt.Println(path)

	proxyURL, err := url.Parse("https://" + host + path)
	if err != nil {
		log.Panic(err)
	}

	if strings.HasSuffix(proxyURL.EscapedPath(), "maxres.jpg") {
		proxyURL.Path = getBestThumbnail(proxyURL.EscapedPath())
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

	defer resp.Body.Close()

	copyHeaders(resp.Header, w.Header(), false)
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}

func ggpht(w http.ResponseWriter, req *http.Request) {
	mu.Lock()
	reqs++
	mu.Unlock()

	const host string = "yt3.ggpht.com"
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Max-Age", "1728000")

	if req.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}

	parts := strings.Split(strings.ToLower(host), ".")
	if len(parts) < 2 {
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
		io.WriteString(w, "Non YouTube domains are not supported.")
		return
	}

	if req.Method != "GET" && req.Method != "HEAD" {
		io.WriteString(w, "Only GET and HEAD requests are allowed.")
		return
	}

	path := req.URL.EscapedPath()
	path = strings.Replace(path, "/ggpht", "", 1)
	path = strings.Replace(path, "/i/", "/", 1)

	proxyURL, err := url.Parse("https://" + host + path)
	if err != nil {
		log.Panic(err)
	}

	fmt.Println(proxyURL)

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

	defer resp.Body.Close()

	copyHeaders(resp.Header, w.Header(), false)
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}
