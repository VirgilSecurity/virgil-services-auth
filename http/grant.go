package http

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"github.com/VirgilSecurity/virgil-services-auth/core"
)

// Grant middleware between http and high level service
type Grant struct {
	Handler core.GrantHandler
}

func (c *Grant) Handshake(ctx *fasthttp.RequestCtx) {
	resp := &response{ctx: ctx}

	var owner core.OwnerCard
	err := json.Unmarshal(ctx.PostBody(), &owner)
	if err != nil {
		resp.Error(core.StatusErrorUUIDValidFailed)
		return
	}
	if owner.ID == "" {
		resp.Error(core.StatusErrorUUIDValidFailed)
		return
	}
	if owner.Scope == "" {
		owner.Scope = "*"
	}

	c.Handler.Handshake(resp, owner)
}

func (c *Grant) Acknowledge(authId string, ctx *fasthttp.RequestCtx) {
	resp := &response{ctx: ctx}

	var msg core.EncryptedMessage
	err := json.Unmarshal(ctx.PostBody(), &msg)
	if err != nil {
		resp.Error(core.StatusErrorEncryptedMessageValidationFailed)
		return
	}

	msg.AttemptId = authId
	c.Handler.Acknowledge(resp, msg)
}
