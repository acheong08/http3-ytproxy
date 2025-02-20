package paths

import (
	"io"
	"net/http"
)

func Root(w http.ResponseWriter, req *http.Request) {
	const msg = `
	HTTP youtube proxy for https://inv.nadeko.net
	https://git.nadeko.net/Fijxu/http3-ytproxy

	Routes:
	/stats
	/health`
	io.WriteString(w, msg)
}
