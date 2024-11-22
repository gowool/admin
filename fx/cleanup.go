package fx

import (
	"go.uber.org/fx"

	"github.com/gowool/admin"
)

func CleanupRefreshTokens(cleanup *admin.CleanupRefreshTokens, lc fx.Lifecycle) {
	lc.Append(fx.StartStopHook(cleanup.Start, cleanup.Stop))
}
