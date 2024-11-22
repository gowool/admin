package admin

import (
	"context"

	"github.com/gowool/rbac"
)

type Assertion2FA struct{}

func (Assertion2FA) Assert(ctx context.Context, _ rbac.Role, _ string) (bool, error) {
	claims := rbac.CtxClaims(ctx)
	if claims == nil || claims.Metadata == nil {
		return false, nil
	}

	scheme, ok1 := claims.Metadata["scheme"].(string)
	if !ok1 {
		return false, nil
	}
	if scheme == "basic" {
		return true, nil
	}

	if bearerFormat, ok2 := claims.Metadata["bearerFormat"].(string); !ok2 || bearerFormat != "JWT" {
		return false, nil
	}

	twoFA, _ := claims.Metadata["2fa"].(bool)
	return twoFA, nil
}
