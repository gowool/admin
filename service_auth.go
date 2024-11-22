package admin

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/gowool/admin/model"
	"github.com/gowool/admin/repository"
)

var _ AuthService = (*DefaultAuthService)(nil)

var (
	ErrAdminNotActive      = errors.New("admin: is not active")
	ErrRefreshTokenExpired = errors.New("admin: refresh token is expired")
)

type AuthService interface {
	Auth(ctx context.Context, username, password string) (model.Session, error)
	OTP(ctx context.Context, a model.Admin, password string) (model.Session, error)
	Refresh(ctx context.Context, token string) (model.Session, error)
	Session(ctx context.Context, a model.Admin, twoFA bool) (model.Session, error)
}

type DefaultAuthService struct {
	config            Config
	adminRepository   repository.Admin
	refreshRepository repository.RefreshToken
}

func NewDefaultAuthService(config Config, adminRepository repository.Admin, refreshRepository repository.RefreshToken) *DefaultAuthService {
	return &DefaultAuthService{
		config:            config,
		adminRepository:   adminRepository,
		refreshRepository: refreshRepository,
	}
}

func (s *DefaultAuthService) Auth(ctx context.Context, username, password string) (model.Session, error) {
	a, err := s.adminRepository.FindByUsername(ctx, username)
	if err != nil {
		return model.Session{}, err
	}

	if err = a.ValidatePassword(password); err != nil {
		return model.Session{}, err
	}

	return s.Session(ctx, a, false)
}

func (s *DefaultAuthService) OTP(ctx context.Context, a model.Admin, password string) (model.Session, error) {
	if err := a.ValidateOTP(password); err != nil {
		return model.Session{}, err
	}

	return s.Session(ctx, a, true)
}

func (s *DefaultAuthService) Refresh(ctx context.Context, token string) (model.Session, error) {
	refresh, err := s.refreshRepository.FindByToken(ctx, token)
	if err != nil {
		return model.Session{}, err
	}

	defer func() {
		_ = s.refreshRepository.Delete(ctx, refresh.ID)
	}()

	if time.Now().After(refresh.Expires) {
		return model.Session{}, ErrRefreshTokenExpired
	}

	a, err := s.adminRepository.FindByID(ctx, refresh.AdminID)
	if err != nil {
		return model.Session{}, err
	}

	var twoFA bool
	if refresh.Metadata != nil {
		twoFA, _ = refresh.Metadata["2fa"].(bool)
	}

	return s.Session(ctx, a, twoFA)
}

func (s *DefaultAuthService) Session(ctx context.Context, a model.Admin, twoFA bool) (model.Session, error) {
	if !a.IsActive {
		return model.Session{}, ErrAdminNotActive
	}

	accessToken, err := NewJWT(
		jwt.MapClaims{
			"sub":   a.Username,
			"email": a.Email,
			"2fa":   twoFA,
			"model": reflect.TypeOf(a).Name(),
		},
		a.Salt+s.config.Secret,
		s.config.AccessTokenDuration,
	)
	if err != nil {
		return model.Session{}, err
	}

	refreshToken := model.RefreshToken{
		AdminID:  a.ID,
		Token:    uuid.NewString(),
		Metadata: map[string]any{"2fa": twoFA},
		Expires:  time.Now().Add(s.config.RefreshTokenDuration),
	}

	if err = s.refreshRepository.Create(ctx, &refreshToken); err != nil {
		return model.Session{}, err
	}

	return model.Session{
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
	}, nil
}
