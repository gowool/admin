package admin

import (
	"context"

	"github.com/gowool/admin/model"
)

type (
	adminKey struct{}
	twoFAKey struct{}
)

func WithAdmin(ctx context.Context, a *model.Admin) context.Context {
	return context.WithValue(ctx, adminKey{}, a)
}

func CtxAdmin(ctx context.Context) *model.Admin {
	admin, _ := ctx.Value(adminKey{}).(*model.Admin)
	return admin
}

func WithTwoFA(ctx context.Context, twoFA bool) context.Context {
	return context.WithValue(ctx, twoFAKey{}, twoFA)
}

func CtxTwoFA(ctx context.Context) bool {
	twoFA, _ := ctx.Value(twoFAKey{}).(bool)
	return twoFA
}
