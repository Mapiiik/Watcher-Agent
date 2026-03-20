package nms

import "time"

type Config struct {
    BaseURL string
    Token   string
    Timeout time.Duration
}
