/*
Copyright © 2025 Keytos alan@keytos.io
*/
package cmd

import (
	"errors"
	"time"
)

// retry runs fn until it succeeds or the retry budget is spent, recording each
// pass as an attempt so that a success which needed a second try stays visible.
//
// The loop counter is local: the previous version decremented the package-level
// retries flag, which made the function single-use and left the global at zero.
func retry(fn func() error) error {
	total := retries + 1
	var errs error

	for i := range total {
		// Sleeping at the top of later iterations rather than at the end of
		// every one avoids a pointless wait after the final failure.
		if i > 0 {
			time.Sleep(retryInterval)
		}

		collector.BeginAttempt(i)
		err := fn()
		collector.FinishAttempt(err)
		if err == nil {
			return nil
		}
		errs = errors.Join(errs, err)
	}

	return errs
}
