package http

import (
	"encoding/json"
	"fmt"

	"github.com/valyala/fasthttp"
	"github.com/virgilsecurity/virgil-services-auth/core"
)

type response struct {
	ctx *fasthttp.RequestCtx
}

func (r *response) Error(code core.ResponseStatus) {
	r.ctx.ResetBody()
	if code == core.StatusErrorAttemptNotFound {
		r.ctx.SetStatusCode(fasthttp.StatusNotFound)
		return
	}
	status := fasthttp.StatusBadRequest
	if code == core.StatusErrorInernalApplicationError {
		status = fasthttp.StatusInternalServerError
	}
	r.ctx.SetStatusCode(status)

	fmt.Fprintf(r.ctx, "{\"code\":%v}", code)
}

func (r *response) Success(model interface{}) {
	r.ctx.SetContentType("application/json")
	err := json.NewEncoder(r.ctx).Encode(model)
	if err != nil {
		r.Error(core.StatusErrorInernalApplicationError)
		return
	}
}
