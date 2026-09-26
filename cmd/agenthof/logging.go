package main

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/agenthof/agenthof/internal/obs"
)

// Environment fallbacks for the operational-logging flags. A flag, when
// given, wins over its variable — the same precedence resolveInvoker gives
// --token over AGENTHOF_TOKEN.
const (
	envLogLevel  = "AGENTHOF_LOG_LEVEL"
	envLogFormat = "AGENTHOF_LOG_FORMAT"
)

// resolveLogConfig turns the --log-level / --log-format values (empty = flag
// not given) into a level and format: flag, then environment, then the
// defaults info / text. An unrecognised value, from either source, is a
// usage error — never silently defaulted.
func resolveLogConfig(levelFlag, formatFlag string, getenv func(string) string) (slog.Level, obs.Format, error) {
	levelStr := levelFlag
	if levelStr == "" {
		levelStr = getenv(envLogLevel)
	}
	if levelStr == "" {
		levelStr = "info"
	}
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return 0, 0, fmt.Errorf("invalid log level %q: --log-level / %s want debug|info|warn|error", levelStr, envLogLevel)
	}

	formatStr := formatFlag
	if formatStr == "" {
		formatStr = getenv(envLogFormat)
	}
	if formatStr == "" {
		formatStr = "text"
	}
	var format obs.Format
	switch strings.ToLower(formatStr) {
	case "text":
		format = obs.FormatText
	case "json":
		format = obs.FormatJSON
	default:
		return 0, 0, fmt.Errorf("invalid log format %q: --log-format / %s want text|json", formatStr, envLogFormat)
	}
	return level, format, nil
}
