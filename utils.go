package main

import (
	"log"
	"net/http"
	"net/url"
	"strings"
)

func copyHeaders(from http.Header, to http.Header, length bool) {
	// Loop over header names
outer:
	for name, values := range from {
		for _, header := range strip_headers {
			if name == header {
				continue outer
			}
		}
		if (name != "Content-Length" || length) && !strings.HasPrefix(name, "Access-Control") {
			// Loop over all values for the name.
			for _, value := range values {
				if strings.Contains(value, "jpeg") {
					continue
				}
				to.Set(name, value)
			}
		}
	}
}

func getBestThumbnail(path string) (newpath string) {

	formats := [4]string{"maxresdefault.jpg", "sddefault.jpg", "hqdefault.jpg", "mqdefault.jpg"}

	for _, format := range formats {
		newpath = strings.Replace(path, "maxres.jpg", format, 1)
		url := "https://i.ytimg.com" + newpath
		resp, _ := h2client.Head(url)
		if resp.StatusCode == 200 {
			return newpath
		}
	}

	return strings.Replace(path, "maxres.jpg", "mqdefault.jpg", 1)
}

func RelativeUrl(in string) (newurl string) {
	segment_url, err := url.Parse(in)
	if err != nil {
		log.Panic(err)
	}
	segment_query := segment_url.Query()
	segment_query.Set("host", segment_url.Hostname())
	segment_url.RawQuery = segment_query.Encode()
	segment_url.Path = path_prefix + segment_url.Path
	return segment_url.RequestURI()
}

func panicHandler(w http.ResponseWriter) {
	if r := recover(); r != nil {
		log.Printf("Panic: %v", r)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
