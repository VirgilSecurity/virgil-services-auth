package http

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/valyala/fasthttp"
)

type FakeChecker struct {
	mock.Mock
}

func (c *FakeChecker) Name() string {
	args := c.Called()
	return args.String(0)
}
func (c *FakeChecker) Info() (info map[string]interface{}, err error) {
	args := c.Called()
	info, _ = args.Get(0).(map[string]interface{})
	err = args.Error(1)
	return
}

func TestStatus_CheckerReturnErr_ReturnBadRequest(t *testing.T) {
	c := &FakeChecker{}
	c.On("Name").Return("test")
	c.On("Info").Return(nil, fmt.Errorf("error"))
	h := HealthChekcer{CheckList: []Checker{c}}
	ctx := makeRequestCtx(nil)
	h.Status(ctx)

	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestStatus_CheckerInfo_ReturnOk(t *testing.T) {
	c := &FakeChecker{}
	c.On("Name").Return("test")
	c.On("Info").Return(nil, nil)
	h := HealthChekcer{CheckList: []Checker{c}}
	ctx := makeRequestCtx(nil)
	h.Status(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
}

func TestInfo_CheckerReturnErr_ReturnBadRequest(t *testing.T) {
	expected, _ := json.Marshal(map[string]interface{}{
		"test": map[string]interface{}{
			"status": fasthttp.StatusBadRequest,
		},
	})
	c := &FakeChecker{}
	c.On("Name").Return("test")
	c.On("Info").Return(nil, fmt.Errorf("error"))
	h := HealthChekcer{CheckList: []Checker{c}}
	ctx := makeRequestCtx(nil)
	h.Info(ctx)

	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Equal(t, expected, ctx.Response.Body())
}

func TestInfo_CheckerInfo_ReturnOk(t *testing.T) {
	expected, _ := json.Marshal(map[string]interface{}{
		"test": map[string]interface{}{
			"status":  fasthttp.StatusOK,
			"latency": 12,
		},
	})
	c := &FakeChecker{}
	c.On("Name").Return("test")
	c.On("Info").Return(map[string]interface{}{"latency": 12}, nil)
	h := HealthChekcer{CheckList: []Checker{c}}
	ctx := makeRequestCtx(nil)
	h.Info(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, expected, ctx.Response.Body())
}
