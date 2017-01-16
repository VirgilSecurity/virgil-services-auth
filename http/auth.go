package http

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"github.com/VirgilSecurity/virgil-services-auth/core"
)

type Auth struct {
	Handler core.AuthHandler
}

func (c *Auth) AccessToken(ctx *fasthttp.RequestCtx) {
	resp := &response{ctx: ctx}

	var ac core.AccessCode
	err := json.Unmarshal(ctx.PostBody(), &ac)
	if err != nil {
		resp.Error(core.StatusErrorCodeNotFound)
		return
	}

	c.Handler.AccessToken(resp, ac)
}

func (c *Auth) Refresh(ctx *fasthttp.RequestCtx) {
	resp := &response{ctx: ctx}

	var t core.Token
	err := json.Unmarshal(ctx.PostBody(), &t)
	if err != nil {
		resp.Error(core.StatusErrorRefreshTokenNotFound)
		return
	}
	c.Handler.Refresh(resp, t.Type, t.Refresh)
}

func (c *Auth) Verify(ctx *fasthttp.RequestCtx) {
	resp := &response{ctx: ctx}

	var t core.Token
	err := json.Unmarshal(ctx.PostBody(), &t)
	if err != nil {
		resp.Error(core.StatusErrorAttemptNotFound)
		return
	}
	c.Handler.Verify(resp, t.Token)
}
