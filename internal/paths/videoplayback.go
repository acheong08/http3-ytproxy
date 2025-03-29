package paths

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"git.nadeko.net/Fijxu/http3-ytproxy/internal/config"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/httpc"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/metrics"
	"git.nadeko.net/Fijxu/http3-ytproxy/internal/utils"
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

func checkRequest(w http.ResponseWriter, req *http.Request, params url.Values) bool {
	host := params.Get("host")

	parts := strings.Split(strings.ToLower(host), ".")
	if len(parts) < 2 {
		w.WriteHeader(400)
		io.WriteString(w, "Invalid hostname.")
		return true
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
		return true
	}

	expire, err := strconv.ParseInt(params.Get("expire"), 10, 64)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, "Expire query string undefined")
		return true
	}

	// Prevent the process of already expired playbacks
	// since they will return 403 from googlevideo server
	if (expire - time.Now().Unix()) <= 0 {
		w.WriteHeader(403)
		io.WriteString(w, "Videoplayback URL has expired.")
		return true
	}

	return false
}

func Videoplayback(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()

	if q.Get("enc") == "true" {
		decryptedQueryParams, err := utils.DecryptQueryParams(req.URL.Query().Get("data"), config.Cfg.Companion.Secret_key)
		if err != nil {
			http.Error(w, "Internal Server Error:\nFailed to decrypt query parameters", http.StatusInternalServerError)
			return
		}

		var structuredDecryptedQueryParams [][]string

		err = json.Unmarshal([]byte(decryptedQueryParams), &structuredDecryptedQueryParams)
		if err != nil {
			http.Error(w, "Internal Server Error:\nFailed to parse query parameters from the decrypted query parameters", http.StatusInternalServerError)
			return
		}

		pot := structuredDecryptedQueryParams[1][1]
		ip := structuredDecryptedQueryParams[0][1]
		q.Del("enc")
		q.Del("data")
		q.Set("pot", pot)
		q.Set("ip", ip)
	}

	if checkRequest(w, req, q) {
		return
	}

	host := q.Get("host")
	title := q.Get("title")
	q.Del("host")
	q.Del("title")

	rangeHeader := req.Header.Get("range")
	var requestBytes string
	if rangeHeader != "" {
		requestBytes = strings.Split(rangeHeader, "=")[1]
	} else {
		requestBytes = ""
	}
	if requestBytes != "" {
		q.Set("range", requestBytes)
	}

	path := req.URL.EscapedPath()

	proxyURL, err := url.Parse("https://" + host + path)
	if err != nil {
		log.Panic(err)
	}

	proxyURL.RawQuery = q.Encode()

	postRequest, err := http.NewRequest("POST", proxyURL.String(), bytes.NewReader(protobuf_body))
	if err != nil {
		log.Panic("Failed to create postRequest:", err)
	}
	headRequest, err := http.NewRequest("HEAD", proxyURL.String(), nil)
	if err != nil {
		log.Panic("Failed to create headRequest:", err)
	}

	postRequest.Header = *videoplayback_headers
	headRequest.Header = *videoplayback_headers

	resp := &http.Response{}

	for i := 0; i < 5; i++ {
		resp, err = httpc.Client.Do(headRequest)
		if err != nil {
			log.Panic("Failed to do HEAD request:", err)
		}
		if resp.Header.Get("Location") != "" {
			new_url, _ := url.Parse(resp.Header.Get("Location"))
			postRequest.URL = new_url
			headRequest.URL = new_url
			postRequest.Host = new_url.Host
			headRequest.Host = new_url.Host
			continue
		} else {
			break
		}
	}

	resp, err = httpc.Client.Do(postRequest)
	if err != nil {
		log.Panic("Failed to do POST request:", err)
	}

	if err := forbiddenChecker(resp, w); err != nil {
		metrics.Metrics.RequestForbidden.Videoplayback.Inc()
		return
	}

	defer resp.Body.Close()

	utils.CopyHeadersNew(resp.Header, w.Header())

	if title != "" {
		content := "attachment; filename=\"" + url.PathEscape(title) + "\"; filename*=UTF-8''" + url.PathEscape(title)
		w.Header().Set("content-disposition", content)
	}

	if requestBytes != "" && resp.StatusCode == http.StatusOK {
		// check for range headers in the forms:
		// "bytes=0-" get full length from start
		// "bytes=500-" get full length from 500 bytes in
		// "bytes=500-1000" get 500 bytes starting from 500
		byteParts := strings.Split(requestBytes, "-")
		firstByte, lastByte := byteParts[0], byteParts[1]
		if lastByte != "" {
			w.Header().Add("content-range", "bytes "+requestBytes+"/*")
			w.WriteHeader(206)
		} else {
			// i.e. "bytes=0-", "bytes=600-"
			// full size of content is able to be calculated, so a full Content-Range header can be constructed
			bytesReceived := resp.Header.Get("content-length")
			firstByteInt, _ := strconv.Atoi(firstByte)
			bytesReceivedInt, _ := strconv.Atoi(bytesReceived)
			// last byte should always be one less than the length
			totalContentLength := firstByteInt + bytesReceivedInt
			lastByte := totalContentLength - 1
			lastByteString := strconv.Itoa(lastByte)
			totalContentLengthString := strconv.Itoa(totalContentLength)
			w.Header().Add("content-range", "bytes "+firstByte+"-"+lastByteString+"/"+totalContentLengthString)
			if firstByte != "0" {
				// only part of the total content returned, 206
				w.WriteHeader(206)
			}
		}
	}

	// w.WriteHeader(resp.StatusCode)

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
				lines[i] = utils.RelativeUrl(line)
			}

			if manifest_re.MatchString(line) {
				url := manifest_re.FindStringSubmatch(line)[1]
				lines[i] = strings.Replace(line, url, utils.RelativeUrl(url), 1)
			}
		}

		io.WriteString(w, strings.Join(lines, "\n"))
	} else {
		io.Copy(w, resp.Body)
	}
}
