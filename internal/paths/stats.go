package paths

import (
	"encoding/json"
	"net/http"
	"time"
)

func Stats(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats_.Uptime = time.Duration(time.Since(programInit).Seconds())
	// stats_.TotalEstablished = int64(cw.totalEstablished)
	// stats_.EstablishedConnections = int64(cw.established)
	// stats_.ActiveConnections = int64(cw.active)
	// stats_.IdleConnections = int64(cw.idle)

	if err := json.NewEncoder(w).Encode(stats_); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
