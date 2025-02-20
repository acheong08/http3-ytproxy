package paths

import (
	"io"
	"net/http"
)

func Health(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)
	io.WriteString(w, "OK")
}
