package radius

import (
	"time"
)

type Config struct {
	Port    uint16
	Timeout time.Duration
	Retries int
}
