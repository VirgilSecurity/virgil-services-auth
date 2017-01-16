package integration

import (
	"fmt"
	"io"
	"net/http"

	"github.com/dghubble/sling"
	"github.com/virgilsecurity/virgil-services-auth/core"
)

func MakeClient() *client {
	return &client{
		c: sling.New().Base("http://localhost:8080"),
	}
}

type errorResponse struct {
	Code       core.ResponseStatus `json:"code"`
	StatusCode int
}

func (e *errorResponse) Error() string {
	return fmt.Sprintln("Error:", e.Code)
}

type client struct {
	c *sling.Sling
}

func (c *client) GetMessage(id string) (*core.EncryptedMessage, error) {
	s, e := new(core.EncryptedMessage), new(errorResponse)
	resp, err := c.c.New().Post("/authorization-grant/actions/get-challenge-message").BodyJSON(core.OwnerCard{
		ID: id,
	}).Receive(s, e)
	if err == io.EOF {
		return nil, &errorResponse{StatusCode: resp.StatusCode}
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		e.StatusCode = resp.StatusCode
		return nil, e
	}
	return s, nil
}

func (c *client) GetCode(msg core.EncryptedMessage) (string, error) {
	s, e := new(core.AccessCode), new(errorResponse)
	resp, err := c.c.New().Post(fmt.Sprintf("/authorization-grant/%s/actions/acknowledge", msg.AttemptId)).BodyJSON(core.EncryptedMessage{
		Message: msg.Message,
	}).Receive(s, e)
	if err == io.EOF {
		return "", &errorResponse{StatusCode: resp.StatusCode}
	}
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		e.StatusCode = resp.StatusCode
		return "", e
	}
	return s.Code, nil
}

func (c *client) GetToken(code string) (*core.Token, error) {
	s, e := new(core.Token), new(errorResponse)
	resp, err := c.c.New().Post("/authorization/actions/obtain-access-code").BodyJSON(core.AccessCode{
		GrantType: "access_code",
		Code:      code,
	}).Receive(s, e)
	if err == io.EOF {
		return nil, &errorResponse{StatusCode: resp.StatusCode}
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		e.StatusCode = resp.StatusCode
		return nil, e
	}
	return s, nil
}

func (c *client) Refresh(token string) (*core.Token, error) {
	s, e := new(core.Token), new(errorResponse)
	resp, err := c.c.New().Post("/authorization/actions/refresh-access-code").BodyJSON(core.Token{
		Type:    "refresh_token",
		Refresh: token,
	}).Receive(s, e)
	if err == io.EOF {
		return nil, &errorResponse{StatusCode: resp.StatusCode}
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		e.StatusCode = resp.StatusCode
		return nil, e
	}
	return s, nil
}

func (c *client) Verify(token string) (string, error) {
	s, e := new(core.OwnerCard), new(errorResponse)
	resp, err := c.c.New().Post("/authorization/actions/verify").BodyJSON(core.Token{
		Token: token,
	}).Receive(s, e)
	if err == io.EOF {
		return "", &errorResponse{StatusCode: resp.StatusCode}
	}
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		e.StatusCode = resp.StatusCode
		return "", e
	}
	return s.ID, nil
}
