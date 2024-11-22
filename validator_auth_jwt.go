package admin

import (
	"reflect"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gowool/rbac"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/cast"

	"github.com/gowool/admin/model"
	"github.com/gowool/admin/repository"
)

func JWTAuthValidator(repo repository.Admin, cfg Config) middleware.KeyAuthValidator {
	return func(token string, c echo.Context) (bool, error) {
		r := c.Request()
		ctx := r.Context()

		claims, _ := ParseUnverifiedJWT(token)
		switch cast.ToString(claimsValue(claims, "model")) {
		case reflect.TypeOf((*model.Admin)(nil)).Elem().Name():
			sub, err := claims.GetSubject()
			if err != nil {
				return false, err
			}

			a, err := repo.FindByUsername(ctx, sub)
			if err != nil {
				return false, err
			}

			if _, err = ParseJWT(token, a.Salt+cfg.Secret); err != nil {
				return false, err
			}

			ctx = WithAdmin(ctx, &a)
			ctx = rbac.WithClaims(ctx, &rbac.Claims{
				Subject: subject{admin: &a},
				Metadata: map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
					"2fa":          cast.ToBool(claimsValue(claims, "2fa")),
				},
			})

			c.SetRequest(r.WithContext(ctx))
			return true, nil
		}
		return false, nil
	}
}

func claimsValue(claims jwt.MapClaims, key string) any {
	if v, ok := claims[key]; ok {
		return v
	}
	return nil
}
