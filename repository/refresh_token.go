package repository

import (
	"context"

	"github.com/gowool/admin/model"
)

type RefreshToken interface {
	Repository[model.RefreshToken, int64]
	FindByAdminID(ctx context.Context, adminID int64) ([]model.RefreshToken, error)
	FindByToken(ctx context.Context, token string) (model.RefreshToken, error)
	DeleteByAdminID(ctx context.Context, adminID int64) error
	DeleteByToken(ctx context.Context, token string) error
	DeleteExpired(ctx context.Context) error
}
