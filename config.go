package admin

import (
	"time"

	"github.com/gowool/admin/internal"
)

type Config struct {
	Secret               string        `json:"secret,omitempty" yaml:"secret,omitempty"`
	AccessTokenDuration  time.Duration `json:"accessTokenDuration,omitempty" yaml:"accessTokenDuration,omitempty"`
	RefreshTokenDuration time.Duration `json:"refreshTokenDuration,omitempty" yaml:"refreshTokenDuration,omitempty"`
	CleanupInterval      time.Duration `json:"cleanupInterval,omitempty" yaml:"cleanupInterval,omitempty"`
}

func (cfg *Config) SetDefaults() {
	if cfg.Secret == "" {
		cfg.Secret = internal.RandomString(50)
	}
	if cfg.AccessTokenDuration == 0 {
		cfg.AccessTokenDuration = 5 * time.Minute
	}
	if cfg.RefreshTokenDuration == 0 {
		cfg.RefreshTokenDuration = 60 * time.Minute
	}
}
