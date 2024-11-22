package model

type Session struct {
	AccessToken  string `json:"accessToken" required:"true"`
	RefreshToken string `json:"refreshToken" required:"true"`
}
