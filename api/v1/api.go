package v1

import (
	"github.com/danielgtaylor/huma/v2"
	"github.com/gowool/echox/api"
	"github.com/gowool/rbac"

	"github.com/gowool/admin"
)

var Info = api.CRUDInfo{Area: "admin", Version: "v1"}

var Security = []map[string][]string{
	{"basic": {}},
	{"bearer": {}},
}

var (
	WithAssertion2FA               = api.WithMetadataItem("assertion_2fa", admin.Assertion2FA{})
	WithAssertionSuperAdmin        = api.WithMetadataItem("assertion_sa", admin.AssertionSuperAdmin{})
	WithAssertionSuperAdminOrOwner = api.WithMetadataItem("assertion_sa_owner", admin.AssertionSuperAdminOrOwner{})
	WithSecurity                   = api.WithSecurity(Security)
	WithNoSecurity                 = func(op *huma.Operation) {
		op.Security = nil
		if op.Metadata == nil {
			return
		}
		for _, v := range op.Metadata {
			switch v := v.(type) {
			case *rbac.Target:
				v.Assertions = nil
			}
		}
	}
	WithNoAssertions = func(op *huma.Operation) {
		if op.Metadata == nil {
			return
		}
		metadata := make(map[string]any)
		for k, v := range op.Metadata {
			switch v := v.(type) {
			case *rbac.Target:
				v.Assertions = nil
				metadata[k] = v
			case rbac.Assertion, []rbac.Assertion:
			default:
				metadata[k] = v
			}
		}
		op.Metadata = metadata
	}
)
