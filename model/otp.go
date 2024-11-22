package model

import (
	"bytes"
	"encoding/base32"
	"errors"

	"github.com/pquerna/otp/totp"

	"github.com/gowool/admin/internal"
)

var ErrOTPNotValid = errors.New("otp: is not valid")

var (
	otpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	chaCha8     = internal.NewChaCha8()
)

const otpSize = 20

type OTP [otpSize]byte

func (otp OTP) Validate(password string) error {
	if totp.Validate(password, otp.String()) {
		return nil
	}
	return ErrOTPNotValid
}

func (otp OTP) Compare(other OTP) int {
	return bytes.Compare(otp[:], other[:])
}

func (otp OTP) IsZero() bool {
	return otp.Compare(OTP{}) == 0
}

func (otp OTP) String() string {
	if otp.IsZero() {
		return ""
	}
	dst := make([]byte, otpEncoding.EncodedLen(len(otp)))
	otpEncoding.Encode(dst, otp[:])
	return internal.String(dst)
}

func NewOTP() (otp OTP, err error) {
	_, err = chaCha8.Read(otp[:])
	return
}

func MustNewOTP() OTP {
	return internal.Must(NewOTP())
}
