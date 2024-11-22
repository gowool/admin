package v1

import (
	"context"
	"reflect"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gowool/echox/api"
	"github.com/labstack/echo/v4"

	"github.com/gowool/admin"
	"github.com/gowool/admin/model"
	"github.com/gowool/admin/repository"
)

type CreateAdminBody struct {
	Avatar   string         `json:"avatar,omitempty" yaml:"avatar,omitempty" required:"true"`
	Email    string         `json:"email,omitempty" yaml:"email,omitempty" required:"true" format:"email" maxLength:"254"`
	Username string         `json:"username,omitempty" yaml:"username,omitempty" required:"true" minLength:"3" maxLength:"100"`
	Password string         `json:"password,omitempty" yaml:"password,omitempty" required:"true" minLength:"8" maxLength:"64"`
	IsActive bool           `json:"isActive,omitempty" yaml:"isActive,omitempty" required:"false"`
	Roles    []string       `json:"roles,omitempty" yaml:"roles,omitempty" required:"true" uniqueItems:"true"`
	Metadata map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty" required:"false"`
}

func (dto CreateAdminBody) Decode(_ context.Context, m *model.Admin) error {
	p, err := model.NewPassword(dto.Password)
	if err != nil {
		return err
	}

	otp, err := model.NewOTP()
	if err != nil {
		return err
	}

	m.Avatar = dto.Avatar
	m.Email = dto.Email
	m.Username = dto.Username
	m.Password = p
	m.OTP = otp
	m.IsActive = dto.IsActive
	m.Roles = dto.Roles
	m.Metadata = dto.Metadata

	*m = m.WithRandomSalt()
	return nil
}

type UpdateAdminBody struct {
	Avatar   *string         `json:"avatar,omitempty" yaml:"avatar,omitempty" required:"false"`
	Email    *string         `json:"email,omitempty" yaml:"email,omitempty" required:"false" format:"email" maxLength:"254"`
	Username *string         `json:"username,omitempty" yaml:"username,omitempty" required:"false" minLength:"3" maxLength:"100"`
	Password *string         `json:"password,omitempty" yaml:"password,omitempty" required:"false" minLength:"8" maxLength:"64"`
	Metadata *map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty" required:"false"`
}

func (dto UpdateAdminBody) Decode(_ context.Context, m *model.Admin) error {
	var changed bool
	if dto.Avatar != nil && *dto.Avatar != m.Avatar {
		m.Avatar = *dto.Avatar
		changed = true
	}
	if dto.Email != nil && *dto.Email != m.Email {
		m.Email = *dto.Email
		changed = true
	}
	if dto.Username != nil && *dto.Username != m.Username {
		m.Username = *dto.Username
		changed = true
	}
	if dto.Password != nil {
		p, err := model.NewPassword(*dto.Password)
		if err != nil {
			return err
		}
		m.Password = p
		changed = true
	}
	if dto.Metadata != nil && !reflect.DeepEqual(*dto.Metadata, m.Metadata) {
		m.Metadata = *dto.Metadata
		changed = true
	}
	if changed {
		*m = m.WithRandomSalt()
	}
	return nil
}

type UpdateRolesBody struct {
	Roles []string `json:"roles,omitempty" yaml:"roles,omitempty" required:"true" uniqueItems:"true"`
}

func (dto UpdateRolesBody) Decode(_ context.Context, m *model.Admin) error {
	m.Roles = dto.Roles
	return nil
}

type IssuerInput struct {
	Issuer string `query:"issuer,omitempty" required:"true"`
}

type AvatarInput struct {
	Male int `query:"male,omitempty" required:"false"`
}

type Admin struct {
	api.List[model.Admin]
	api.Read[model.Admin, int64]
	api.Create[CreateAdminBody, model.Admin, int64]
	api.Update[UpdateAdminBody, model.Admin, int64]
	updateRoles api.Update[UpdateRolesBody, model.Admin, int64]
	refreshRepo repository.RefreshToken
	op          func(options ...api.Option) huma.Operation
}

func NewAdmin(r repository.Admin, refreshRepo repository.RefreshToken, errorTransformer api.ErrorTransformerFunc) Admin {
	op := api.Operation(WithSecurity, WithAssertion2FA, api.WithPath("/admin"), api.WithAddTags("admin"))

	return Admin{
		List:        api.NewList(r.FindAndCount, errorTransformer, op(api.WithSummary("Get admins"))),
		Read:        api.NewRead(r.FindByID, errorTransformer, op(api.WithSummary("Get admin"), api.WithAddPath("/{id}"))),
		Create:      api.NewCreate[CreateAdminBody](r.Create, errorTransformer, op(WithAssertionSuperAdmin, api.WithPost, api.WithSummary("Create admin"))),
		Update:      api.NewUpdate[UpdateAdminBody](r.FindByID, r.Update, errorTransformer, op(WithAssertionSuperAdminOrOwner, api.WithPatch, api.WithSummary("Update admin"), api.WithAddPath("/{id}"))),
		updateRoles: api.NewUpdate[UpdateRolesBody](r.FindByID, r.Update, errorTransformer, op(WithAssertionSuperAdmin, api.WithPatch, api.WithSummary("Update admin roles"), api.WithAddPath("/{id}/roles"))),
		refreshRepo: refreshRepo,
		op:          op,
	}
}

func (Admin) Area() string {
	return Info.Area
}

func (Admin) Version() string {
	return Info.Version
}

func (r Admin) Register(e *echo.Echo, humaAPI huma.API) {
	r.List.Register(e, humaAPI)
	r.Read.Register(e, humaAPI)
	r.Create.Register(e, humaAPI)
	r.Update.Register(e, humaAPI)
	r.updateRoles.Register(e, humaAPI)
	api.Register(humaAPI, api.Transform(r.List.ErrorTransformer, r.me), r.op(api.WithSummary("Me"), api.WithAddPath("/me")))
	api.Register(humaAPI, api.Transform(r.List.ErrorTransformer, r.otpKey), r.op(api.WithSummary("OTP KEy"), api.WithAddPath("/otp-key")))
	api.Register(humaAPI, api.Transform(r.List.ErrorTransformer, r.avatar), r.op(api.WithSummary("Avatar"), api.WithAddPath("/avatar")))
	api.Register(humaAPI, api.Transform(r.List.ErrorTransformer, r.activate), r.op(WithAssertionSuperAdmin, api.WithPatch, api.WithSummary("Activate"), api.WithAddPath("/{id}/activate")))
	api.Register(humaAPI, api.Transform(r.List.ErrorTransformer, r.deactivate), r.op(WithAssertionSuperAdmin, api.WithPatch, api.WithSummary("Deactivate"), api.WithAddPath("/{id}/deactivate")))
}

func (r Admin) me(ctx context.Context, _ *struct{}) (*api.Response[*model.Admin], error) {
	return &api.Response[*model.Admin]{Body: admin.CtxAdmin(ctx)}, nil
}

func (r Admin) otpKey(ctx context.Context, in *IssuerInput) (*api.Response[string], error) {
	key, err := admin.CtxAdmin(ctx).OTPKey(in.Issuer)

	return &api.Response[string]{Body: key}, err
}

func (r Admin) avatar(_ context.Context, in *AvatarInput) (*api.Response[string], error) {
	return &api.Response[string]{Body: admin.GenerateAvatar(in.Male == 1)}, nil
}

func (r Admin) activate(ctx context.Context, in *api.IDInput[int64]) (*struct{}, error) {
	a, err := r.Read.Finder(ctx, in.ID)
	if err != nil {
		return nil, err
	}

	a.IsActive = true
	err = r.Update.Saver(ctx, &a)

	return nil, err
}

func (r Admin) deactivate(ctx context.Context, in *api.IDInput[int64]) (*struct{}, error) {
	a, err := r.Read.Finder(ctx, in.ID)
	if err != nil {
		return nil, err
	}

	a.IsActive = false
	a = a.WithRandomSalt()

	if err = r.Update.Saver(ctx, &a); err != nil {
		return nil, err
	}

	err = r.refreshRepo.DeleteByAdminID(ctx, a.ID)
	return nil, err
}
