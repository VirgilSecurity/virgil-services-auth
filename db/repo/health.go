package repo

import (
	"time"

	mgo "gopkg.in/mgo.v2"
)

type HealthChecker struct {
	S *mgo.Session
}

func (h *HealthChecker) Name() string {
	return "mongo"
}
func (h *HealthChecker) Info() (map[string]interface{}, error) {
	start := time.Now()
	err := h.S.Ping()
	end := time.Now()

	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"latency": end.Sub(start) / time.Millisecond,
	}, nil
}
