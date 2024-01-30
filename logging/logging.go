package logging

import (
    "os"
    "fmt"
    "log/slog"

    "github.com/go-chi/httplog/v2"
)

var Logger *slog.Logger
var HttpLogger *httplog.Logger

func InitLogging(level string) {
    opts := &slog.HandlerOptions{
        Level: slog.LevelInfo,
    }

    httpOpts := &httplog.Options{
        LogLevel:         slog.LevelInfo,
        Concise:          true,
        RequestHeaders:   false,
        MessageFieldName: "msg",
    }

    switch level {
        case "debug":
            opts.Level = slog.LevelDebug
            httpOpts.LogLevel = slog.LevelDebug
        case "info":
            opts.Level = slog.LevelInfo
            httpOpts.LogLevel = slog.LevelInfo
        case "warn":
            opts.Level = slog.LevelWarn
            httpOpts.LogLevel = slog.LevelWarn
        case "error":
            opts.Level = slog.LevelError
            httpOpts.LogLevel = slog.LevelError
        default:
            fmt.Printf("invalid loglevel %v", level)
            os.Exit(1)
    }

    Logger = slog.New(slog.NewTextHandler(os.Stdout, opts))
    HttpLogger = &httplog.Logger{
        Logger: Logger,
        Options: *httpOpts,
    }
}

