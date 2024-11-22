package fx

import (
	"github.com/gowool/echox/api"
	"go.uber.org/fx"

	"github.com/gowool/admin"
	"github.com/gowool/admin/api/v1"
)

var (
	OptionAuthorizer    = fx.Provide(admin.Authorizer)
	OptionAPIAuthorizer = fx.Provide(admin.APIAuthorizer)

	OptionBasicAuthValidator = fx.Provide(admin.BasicAuthValidator)
	OptionJWTAuthValidator   = fx.Provide(admin.JWTAuthValidator)

	OptionService              = fx.Provide(fx.Annotate(admin.NewDefaultService, fx.As(new(admin.Service))))
	OptionAuthService          = fx.Provide(fx.Annotate(admin.NewDefaultAuthService, fx.As(new(admin.AuthService))))
	OptionCleanupRefreshTokens = fx.Provide(admin.NewCleanupRefreshTokens)

	OptionAdminAPI = fx.Provide(api.AsHandler(v1.NewAdmin))
	OptionAuthAPI  = fx.Provide(api.AsHandler(v1.NewAuth))
)
