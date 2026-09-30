package refrunner

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

// Serve runs handler on ln until SIGINT or SIGTERM, then closes the server
// (cutting every connection, which cancels every in-flight request's
// context), runs onShutdown — the runtime's own teardown: end sessions,
// remove compartments — removes the socket file, and returns nil. A serve
// failure that is not the orderly close is returned as is.
func Serve(ln net.Listener, handler http.Handler, logger *slog.Logger, onShutdown func()) error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	return serve(ln, handler, logger, onShutdown, stop)
}

// serve is Serve with the signal source injected, so a test can shut it down
// without signalling the test binary.
func serve(ln net.Listener, handler http.Handler, logger *slog.Logger, onShutdown func(), stop <-chan os.Signal) error {
	srv := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-stop
		logger.Info("shutting down")
		_ = srv.Close()
		onShutdown()
		_ = os.Remove(ln.Addr().String())
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-done
	return nil
}
