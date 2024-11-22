package admin

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/gowool/admin/repository"
)

type CleanupRefreshTokens struct {
	config            Config
	refreshRepository repository.RefreshToken
	logger            *zap.Logger
	stopCleanup       chan bool
	wg                sync.WaitGroup
}

func NewCleanupRefreshTokens(config Config, refreshRepository repository.RefreshToken, logger *zap.Logger) *CleanupRefreshTokens {
	return &CleanupRefreshTokens{
		config:            config,
		refreshRepository: refreshRepository,
		logger:            logger,
	}
}

func (c *CleanupRefreshTokens) Start() {
	if c.config.CleanupInterval == 0 {
		return
	}

	if c.stopCleanup == nil {
		c.stopCleanup = make(chan bool)
	}

	c.wg.Add(1)
	go c.start(c.config.CleanupInterval)
}

func (c *CleanupRefreshTokens) Stop() {
	if c.config.CleanupInterval == 0 {
		return
	}

	if c.stopCleanup == nil {
		return
	}

	c.stopCleanup <- true
	c.wg.Wait()
}

func (c *CleanupRefreshTokens) start(interval time.Duration) {
	defer c.wg.Done()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ticker.C:
			if err := c.refreshRepository.DeleteExpired(ctx); err != nil {
				c.logger.Error("delete expired refresh tokens", zap.Error(err))
			}
		case <-c.stopCleanup:
			ticker.Stop()
			return
		}
	}
}
