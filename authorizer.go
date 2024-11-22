package admin

import (
	"github.com/danielgtaylor/huma/v2"
	"github.com/gowool/echox"
	"github.com/gowool/echox/api"
	"github.com/gowool/rbac"
	"github.com/labstack/echo/v4"
)

func Authorizer(authorizer rbac.Authorizer) echox.Authorizer {
	return rbac.RequestAuthorizer(authorizer, nil)
}

func APIAuthorizer(authorizer echox.Authorizer) api.Authorizer {
	return func(c huma.Context) error {
		xCtx, ok := c.(interface{ EchoContext() echo.Context })
		if !ok {
			return rbac.ErrDeny
		}

		ctx := c.Context()
		assertions := rbac.CtxAssertions(ctx)
		assertions = append(make([]rbac.Assertion, 0, len(assertions)), assertions...)

		target := rbac.CtxTarget(ctx)

		if o := c.Operation(); o.Metadata != nil {
			for _, value := range o.Metadata {
				switch value := value.(type) {
				case *rbac.Target:
					if target == nil {
						target = value
					}
				case rbac.Assertion:
					assertions = append(assertions, value)
				case []rbac.Assertion:
					assertions = append(assertions, value...)
				}
			}
		}

		ctx = rbac.WithAssertions(ctx, assertions...)
		ctx = rbac.WithTarget(ctx, target)

		return authorizer(xCtx.EchoContext().Request().WithContext(ctx))
	}
}
