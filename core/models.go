package core

type AccessCode struct {
	GrantType string `json:"grant_type,omitted"`
	Code      string `json:"code"`
}

type Token struct {
	Token     string `json:"access_token,omitted"`
	Refresh   string `json:"refresh_token,omitted"`
	ExpiresIn int    `json:"expires_in,omitted"`
	Type      string `json:"token_type,omitted"`
}

type OwnerCard struct {
	ID    string `json:"resource_owner_virgil_card_id"`
	Scope string `json:"-"`
}

type EncryptedMessage struct {
	AttemptId string `json:"authorization_grant_id"`
	Message   []byte `json:"encrypted_message"`
}
