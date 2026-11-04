package protocol

import "errors"

// NoRetryError marks an operation that already reached a definitive local or
// application result. Refreshing credentials or switching egress cannot repair
// this result and may replay an accepted request.
type NoRetryError struct{ Cause error }

func (e *NoRetryError) Error() string { return e.Cause.Error() }
func (e *NoRetryError) Unwrap() error { return e.Cause }

func MarkNoRetry(err error) error {
	if err == nil || IsNoRetry(err) {
		return err
	}
	return &NoRetryError{Cause: err}
}

func IsNoRetry(err error) bool { var terminal *NoRetryError; return errors.As(err, &terminal) }
