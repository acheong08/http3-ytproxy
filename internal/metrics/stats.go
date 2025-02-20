package metrics

import (
	"runtime"
	"time"
)

type statusJson struct {
	Version                 string        `json:"version"`
	Uptime                  time.Duration `json:"uptime"`
	RequestCount            int64         `json:"requestCount"`
	RequestPerSecond        int64         `json:"requestPerSecond"`
	RequestPerMinute        int64         `json:"requestPerMinute"`
	TotalConnEstablished    int64         `json:"totalEstablished"`
	EstablishedConnections  int64         `json:"establishedConnections"`
	ActiveConnections       int64         `json:"activeConnections"`
	IdleConnections         int64         `json:"idleConnections"`
	RequestsForbiddenPerSec struct {
		Videoplayback int64 `json:"videoplayback"`
	}
	RequestsForbidden struct {
		Videoplayback int64 `json:"videoplayback"`
		Vi            int64 `json:"vi"`
		Ggpht         int64 `json:"ggpht"`
	} `json:"requestsForbidden"`
}

var stats_ = statusJson{
	Version:                version + "-" + runtime.GOARCH,
	Uptime:                 0,
	RequestCount:           0,
	RequestPerSecond:       0,
	RequestPerMinute:       0,
	TotalConnEstablished:   0,
	EstablishedConnections: 0,
	ActiveConnections:      0,
	IdleConnections:        0,
	RequestsForbiddenPerSec: struct {
		Videoplayback int64 `json:"videoplayback"`
	}{
		Videoplayback: 0,
	},
	RequestsForbidden: struct {
		Videoplayback int64 `json:"videoplayback"`
		Vi            int64 `json:"vi"`
		Ggpht         int64 `json:"ggpht"`
	}{
		Videoplayback: 0,
		Vi:            0,
		Ggpht:         0,
	},
}
