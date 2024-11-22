package admin

import (
	"github.com/gowool/rbac"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"

	"github.com/gowool/admin/model"
	"github.com/gowool/admin/repository"
)

type subject struct {
	admin *model.Admin
}

func (s subject) Identifier() string {
	return s.admin.Email
}

func (s subject) Roles() []string {
	return s.admin.Roles
}

func BasicAuthValidator(repo repository.Admin, logger *zap.Logger) middleware.BasicAuthValidator {
	return func(username, password string, c echo.Context) (bool, error) {
		r := c.Request()
		ctx := r.Context()

		a, err := repo.FindByUsername(ctx, username)
		if err != nil {
			logger.Warn("find admin", zap.String("username", username), zap.Error(err))
			return false, nil
		}
		if err = a.Password.Validate(password); err != nil {
			logger.Warn("validate password", zap.Int64("id", a.ID), zap.String("username", username), zap.Error(err))
			return false, nil
		}

		ctx = WithAdmin(ctx, &a)
		ctx = rbac.WithClaims(ctx, &rbac.Claims{
			Subject: subject{admin: &a},
			Metadata: map[string]any{
				"type":   "http",
				"scheme": "basic",
			},
		})

		c.SetRequest(r.WithContext(ctx))
		return true, nil
	}
}
