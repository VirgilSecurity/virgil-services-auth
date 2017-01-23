package services

import (
	"time"

	"gopkg.in/virgil.v4"
)

type VirgilGetClient interface {
	GetCard(id string) (*virgil.Card, error)
}
type CardsServiceHealthChecker struct {
	Vclient VirgilGetClient
	CardId  string
}

func (h *CardsServiceHealthChecker) Name() string {
	return "cards-service"
}
func (h *CardsServiceHealthChecker) Info() (map[string]interface{}, error) {
	start := time.Now()
	_, err := h.Vclient.GetCard(h.CardId)
	end := time.Now()

	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"latency": end.Sub(start) / time.Millisecond,
	}, nil
}
