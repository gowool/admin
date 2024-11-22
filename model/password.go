package model

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/gowool/admin/internal"
)

var (
	ErrPasswordIsEmpty  = errors.New("password: is empty")
	ErrPasswordNotValid = errors.New("password: is not valid")
	ErrPasswordShort    = errors.New("password: is too short, must be at least 8 characters long")
	ErrPasswordLong     = errors.New("password: is too long, must be at most 64 characters long")
)

type Password []byte

func (p Password) Validate(password string) error {
	err := bcrypt.CompareHashAndPassword(p, internal.Bytes(password))
	if err != nil {
		return ErrPasswordNotValid
	}
	return nil
}

func (p Password) IsZero() bool {
	return len(p) == 0
}

func (p Password) String() string {
	return internal.String(p)
}

func NewPassword(password string) (Password, error) {
	if password == "" {
		return Password{}, ErrPasswordIsEmpty
	}
	if len(password) < 8 {
		return Password{}, ErrPasswordShort
	}
	if len(password) > 64 {
		return Password{}, ErrPasswordLong
	}
	hash, err := bcrypt.GenerateFromPassword(internal.Bytes(password), bcrypt.DefaultCost)
	if err != nil {
		return Password{}, fmt.Errorf("failed to hash password, err: %w", err)
	}
	return hash, nil
}
