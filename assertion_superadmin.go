package admin

import (
	"context"
	"fmt"
	"strings"

	"github.com/gowool/rbac"
)

const RoleSuperAdmin = "ROLE_SUPER_ADMIN"

type AssertionSuperAdmin struct{}

func (AssertionSuperAdmin) Assert(_ context.Context, role rbac.Role, _ string) (bool, error) {
	return role.Name() == RoleSuperAdmin, nil
}

type AssertionSuperAdminOrOwner struct{}

func (AssertionSuperAdminOrOwner) Assert(ctx context.Context, role rbac.Role, _ string) (bool, error) {
	if role.Name() == RoleSuperAdmin {
		return true, nil
	}

	a := CtxAdmin(ctx)
	if a == nil {
		return false, nil
	}

	info := rbac.CtxRequestInfo(ctx)

	return strings.Contains(info.URL.Path, fmt.Sprintf("/admin/%d", a.ID)), nil
}
