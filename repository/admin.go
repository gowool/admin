package repository

import (
	"context"

	"github.com/gowool/admin/model"
)

type Admin interface {
	Repository[model.Admin, int64]
	FindByUsername(ctx context.Context, username string) (model.Admin, error)
	FindByEmail(ctx context.Context, email string) (model.Admin, error)
}
