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
		case "/v4/health/status":
			r.HealthChecker.Status(ctx)
		case "/v4/health/info":
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
	case path == "/v4/authorization/actions/obtain-access-token":
		r.Auth.AccessToken(ctx)

	case path == "/v4/authorization/actions/refresh-access-token":
		r.Auth.Refresh(ctx)

	case path == "/v4/authorization/actions/verify":
		r.Auth.Verify(ctx)

	case path == "/v4/authorization-grant/actions/get-challenge-message":
		r.Grant.Handshake(ctx)

	case strings.HasPrefix(path, "/v4/authorization-grant/") &&
		strings.HasSuffix(path, "/actions/acknowledge"):
		startAuthId, endAuthId := len("/v4/authorization-grant/"), strings.Index(path, "/actions/acknowledge")
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
