package http

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
)

type Checker interface {
	Name() string
	Info() (map[string]interface{}, error)
}

type HealthResult struct {
	Name   string
	Status int
	Info   map[string]interface{}
}

type HealthChecker struct {
	CheckList []Checker
}

func (h *HealthChecker) Status(ctx *fasthttp.RequestCtx) {
	r := h.Check()
	for _, v := range r {
		if v.Status != fasthttp.StatusOK {
			ctx.SetStatusCode(v.Status)
			return
		}
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (h *HealthChecker) Info(ctx *fasthttp.RequestCtx) {
	resp := make(map[string]interface{})
	r := h.Check()
	ctx.SetStatusCode(fasthttp.StatusOK)
	for _, v := range r {
		if v.Status != fasthttp.StatusOK {
			ctx.SetStatusCode(v.Status)
		}
		info := v.Info
		if info == nil {
			info = make(map[string]interface{})
		}
		info["status"] = v.Status
		resp[v.Name] = info
	}
	b, _ := json.Marshal(resp)
	ctx.Write(b)
}

func (h *HealthChecker) Check() []HealthResult {
	r := make([]HealthResult, 0)
	for _, v := range h.CheckList {
		m := HealthResult{}
		m.Name = v.Name()
		m.Status = fasthttp.StatusOK

		info, err := v.Info()
		if err != nil {
			m.Status = fasthttp.StatusBadRequest
		}
		m.Info = info
		r = append(r, m)
	}
	return r
}
