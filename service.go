package admin

import (
	"context"

	"github.com/gowool/admin/model"
	"github.com/gowool/admin/repository"
)

var _ Service = (*DefaultService)(nil)

type Service interface {
	Get(ctx context.Context, username string) (model.Admin, error)
	GetOTPKey(ctx context.Context, username, issuer string) (string, error)
	Create(ctx context.Context, email, username, password, avatar string, isActive bool, roles ...string) (model.Admin, error)
	Change(ctx context.Context, username string, fn func(a *model.Admin) (bool, error)) (model.Admin, error)
	ChangeAvatar(ctx context.Context, username, avatar string) (model.Admin, error)
	ChangeEmail(ctx context.Context, username, email string) (model.Admin, error)
	ChangeUsername(ctx context.Context, oldUsername, newUsername string) (model.Admin, error)
	ChangePassword(ctx context.Context, username, password string) (model.Admin, error)
	ChangeRoles(ctx context.Context, username string, roles ...string) (model.Admin, error)
	ChangeOTP(ctx context.Context, username string) (model.Admin, error)
	Activate(ctx context.Context, username string) (model.Admin, error)
	Deactivate(ctx context.Context, username string) (model.Admin, error)
}

type DefaultService struct {
	adminRepository   repository.Admin
	refreshRepository repository.RefreshToken
}

func NewDefaultService(adminRepository repository.Admin, refreshRepository repository.RefreshToken) *DefaultService {
	return &DefaultService{
		adminRepository:   adminRepository,
		refreshRepository: refreshRepository,
	}
}

func (s *DefaultService) Get(ctx context.Context, username string) (model.Admin, error) {
	return s.adminRepository.FindByUsername(ctx, username)
}

func (s *DefaultService) GetOTPKey(ctx context.Context, username, issuer string) (string, error) {
	a, err := s.Get(ctx, username)
	if err != nil {
		return "", err
	}
	return a.OTPKey(issuer)
}

func (s *DefaultService) Create(ctx context.Context, email, username, password, avatar string, isActive bool, roles ...string) (model.Admin, error) {
	p, err := model.NewPassword(password)
	if err != nil {
		return model.Admin{}, err
	}

	otp, err := model.NewOTP()
	if err != nil {
		return model.Admin{}, err
	}

	a := model.Admin{
		Avatar:   avatar,
		Email:    email,
		Username: username,
		Password: p,
		OTP:      otp,
		Roles:    roles,
		IsActive: isActive,
	}
	a = a.WithRandomSalt()

	if err = s.adminRepository.Create(ctx, &a); err != nil {
		return model.Admin{}, err
	}
	return a, nil
}

func (s *DefaultService) Change(ctx context.Context, username string, fn func(a *model.Admin) (bool, error)) (model.Admin, error) {
	a, err := s.Get(ctx, username)
	if err != nil {
		return model.Admin{}, err
	}

	clean, err := fn(&a)
	if err != nil {
		return model.Admin{}, err
	}

	if err = s.adminRepository.Update(ctx, &a); err != nil {
		return model.Admin{}, err
	}

	if clean {
		_ = s.refreshRepository.DeleteByAdminID(ctx, a.ID)
	}

	return a, nil
}

func (s *DefaultService) ChangeAvatar(ctx context.Context, username, avatar string) (model.Admin, error) {
	return s.Change(ctx, username, func(a *model.Admin) (bool, error) {
		a.Avatar = avatar
		*a = a.WithRandomSalt()
		return false, nil
	})
}

func (s *DefaultService) ChangeEmail(ctx context.Context, username, email string) (model.Admin, error) {
	return s.Change(ctx, username, func(a *model.Admin) (bool, error) {
		a.Email = email
		*a = a.WithRandomSalt()
		return false, nil
	})
}

func (s *DefaultService) ChangeUsername(ctx context.Context, oldUsername, newUsername string) (model.Admin, error) {
	return s.Change(ctx, oldUsername, func(a *model.Admin) (bool, error) {
		a.Username = newUsername
		*a = a.WithRandomSalt()
		return false, nil
	})
}

func (s *DefaultService) ChangePassword(ctx context.Context, username, password string) (model.Admin, error) {
	return s.Change(ctx, username, func(a *model.Admin) (clean bool, err error) {
		a.Password, err = model.NewPassword(password)
		if err != nil {
			return
		}
		*a = a.WithRandomSalt()
		return true, nil
	})
}

func (s *DefaultService) ChangeRoles(ctx context.Context, username string, roles ...string) (model.Admin, error) {
	return s.Change(ctx, username, func(a *model.Admin) (bool, error) {
		a.Roles = roles
		*a = a.WithRandomSalt()
		return true, nil
	})
}

func (s *DefaultService) ChangeOTP(ctx context.Context, username string) (model.Admin, error) {
	return s.Change(ctx, username, func(a *model.Admin) (clean bool, err error) {
		a.OTP, err = model.NewOTP()
		if err != nil {
			return
		}
		if err == nil {
			*a = a.WithRandomSalt()
		}
		return true, nil
	})
}

func (s *DefaultService) Activate(ctx context.Context, username string) (model.Admin, error) {
	return s.Change(ctx, username, func(a *model.Admin) (bool, error) {
		a.IsActive = true
		return false, nil
	})
}

func (s *DefaultService) Deactivate(ctx context.Context, username string) (model.Admin, error) {
	return s.Change(ctx, username, func(a *model.Admin) (bool, error) {
		a.IsActive = false
		*a = a.WithRandomSalt()
		return true, nil
	})
}
