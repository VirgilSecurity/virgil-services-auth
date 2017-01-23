package http

import (
	"strings"

	"github.com/valyala/fasthttp"
)

type Router struct {
	Grant         *Grant
	Auth          *Auth
	HealthChecker *HealthChecker
}

func (r *Router) Handler(ctx *fasthttp.RequestCtx) {
	if ctx.IsGet() {
		switch string(ctx.Path()) {
		case "/health/status":
			r.HealthChecker.Status(ctx)
		case "/health/info":
			r.HealthChecker.Info(ctx)
		default:
			ctx.Error("", fasthttp.StatusMethodNotAllowed)
		}
		return
	}

	if !ctx.IsPost() {
		ctx.Error("", fasthttp.StatusMethodNotAllowed)
		return
	}

	path := string(ctx.Path())

	switch {
	case path == "/authorization/actions/obtain-access-token":
		r.Auth.AccessToken(ctx)

	case path == "/authorization/actions/refresh-access-token":
		r.Auth.Refresh(ctx)

	case path == "/authorization/actions/verify":
		r.Auth.Verify(ctx)

	case path == "/authorization-grant/actions/get-challenge-message":
		r.Grant.Handshake(ctx)

	case strings.HasPrefix(path, "/authorization-grant/") &&
		strings.HasSuffix(path, "/actions/acknowledge"):
		startAuthId, endAuthId := len("/authorization-grant/"), strings.Index(path, "/actions/acknowledge")
		if startAuthId > endAuthId {
			ctx.Error("", fasthttp.StatusMethodNotAllowed)
			return
		}

		authId := ctx.Path()[startAuthId:endAuthId]
		r.Grant.Acknowledge(string(authId), ctx)
	default:
		ctx.Error("", fasthttp.StatusMethodNotAllowed)
		return
	}
}
