package model

import "time"

type RefreshToken struct {
	ID       int64          `json:"id,omitempty" yaml:"id,omitempty" required:"true"`
	AdminID  int64          `json:"adminID,omitempty" yaml:"adminID,omitempty" required:"true"`
	Token    string         `json:"token,omitempty" yaml:"token,omitempty" required:"true"`
	Metadata map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty" required:"false"`
	Created  time.Time      `json:"created,omitempty" yaml:"created,omitempty" required:"true"`
	Updated  time.Time      `json:"updated,omitempty" yaml:"updated,omitempty" required:"true"`
	Expires  time.Time      `json:"expires,omitempty" yaml:"expires,omitempty" required:"true"`
}

func (t RefreshToken) GetID() int64 {
	return t.ID
}
