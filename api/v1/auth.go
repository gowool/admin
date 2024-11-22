package v1

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gowool/echox/api"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"github.com/gowool/admin"
	"github.com/gowool/admin/model"
)

type SignIn struct {
	Body struct {
		Username string `json:"username,omitempty" required:"true" minLength:"3" maxLength:"100"`
		Password string `json:"password,omitempty" required:"true" minLength:"8" maxLength:"64"`
	}
}

type OTP struct {
	Body struct {
		Password string `json:"password,omitempty" required:"true" minLength:"6" maxLength:"6" pattern:"[0-9]+"`
	}
}

type RefreshToken struct {
	Body struct {
		RefreshToken string `json:"refreshToken,omitempty" required:"true"`
	}
}

type Auth struct {
	service admin.AuthService
	logger  *zap.Logger
}

func NewAuth(service admin.AuthService, logger *zap.Logger) Auth {
	return Auth{
		service: service,
		logger:  logger.Named("auth"),
	}
}

func (Auth) Area() string {
	return Info.Area
}

func (Auth) Version() string {
	return Info.Version
}

func (r Auth) Register(_ *echo.Echo, humaAPI huma.API) {
	op := api.Operation(api.WithPost, api.WithPath("/auth"), api.WithAddTags("auth"))

	api.Register(humaAPI, r.signIn, op(api.WithSummary("Sign In"), api.WithAddPath("/sign-in")))
	api.Register(humaAPI, r.otp, op(WithSecurity, api.WithSummary("OTP"), api.WithAddPath("/otp")))
	api.Register(humaAPI, r.refreshToken, op(api.WithSummary("Refresh Token"), api.WithAddPath("/refresh-token")))
}

func (r Auth) signIn(ctx context.Context, in *SignIn) (*api.Response[model.Session], error) {
	return r.normalize(r.service.Auth(ctx, in.Body.Username, in.Body.Password))
}

func (r Auth) otp(ctx context.Context, in *OTP) (*api.Response[model.Session], error) {
	a := admin.CtxAdmin(ctx)
	if a == nil {
		return r.normalize(model.Session{}, errors.New("invalid context, admin not found"))
	}
	return r.normalize(r.service.OTP(ctx, *a, in.Body.Password))
}

func (r Auth) refreshToken(ctx context.Context, in *RefreshToken) (*api.Response[model.Session], error) {
	return r.normalize(r.service.Refresh(ctx, in.Body.RefreshToken))
}

func (r Auth) normalize(session model.Session, err error) (*api.Response[model.Session], error) {
	if err == nil {
		return &api.Response[model.Session]{
			Body: session,
		}, nil
	}

	r.logger.Error("login failed", zap.Error(err))
	return nil, huma.Error400BadRequest("Login failed, please try again")
}
