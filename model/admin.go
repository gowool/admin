package model

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/gowool/admin/internal"
)

type Admin struct {
	ID       int64          `json:"id,omitempty" yaml:"id,omitempty" required:"true"`
	Avatar   string         `json:"avatar,omitempty" yaml:"avatar,omitempty" required:"true"`
	Email    string         `json:"email,omitempty" yaml:"email,omitempty" required:"true" format:"email"`
	Username string         `json:"username,omitempty" yaml:"username,omitempty" required:"true"`
	Salt     string         `json:"_" yaml:"-" hidden:"true"`
	Password Password       `json:"-" yaml:"-" hidden:"true"`
	OTP      OTP            `json:"-" yaml:"-" hidden:"true"`
	IsActive bool           `json:"isActive,omitempty" yaml:"isActive,omitempty" required:"false"`
	Roles    []string       `json:"roles,omitempty" yaml:"roles,omitempty" required:"true"`
	Metadata map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty" required:"false"`
	Created  time.Time      `json:"created,omitempty" yaml:"created,omitempty" required:"true"`
	Updated  time.Time      `json:"updated,omitempty" yaml:"updated,omitempty" required:"true"`
}

func (a Admin) GetID() int64 {
	return a.ID
}

func (a Admin) WithRandomSalt() Admin {
	a.Salt = internal.RandomString(50)
	return a
}

func (a Admin) ValidatePassword(password string) error {
	return a.Password.Validate(password)
}

func (a Admin) ValidateOTP(password string) error {
	return a.OTP.Validate(password)
}

func (a Admin) OTPKey(issuer string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: a.Email,
		Period:      30,
		SecretSize:  otpSize,
		Secret:      a.OTP[:],
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", err
	}
	return key.String(), nil
}
