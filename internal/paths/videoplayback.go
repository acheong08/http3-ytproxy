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

func checkRequest(w http.ResponseWriter, req *http.Request, params url.Values) {
	host := params.Get("host")

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
		return
	}

	host := q.Get("host")
	q.Del("host")

	if req.Header.Get("Range") != "" {
		q.Set("range", strings.Split(req.Header.Get("Range"), "=")[1])
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
