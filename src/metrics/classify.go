/*
Copyright © 2025

Failure classification.

The radius and eap packages return plain fmt.Errorf strings from roughly forty
sites, so classifying by matching those strings would be brittle and would rot
the first time an upstream message is reworded. Three mechanisms are used
instead, in order of precedence:

 1. A StageError wrapper at the dozen decision points worth being precise
    about.
 2. The RADIUS response code recorded by the session, which is a fact rather
    than an inference.
 3. The stage high-water mark, which attributes anything unrecognized to the
    furthest point the exchange actually reached.
*/
package metrics

import (
	"errors"
	"net"
)

// Classify maps an error onto a result and the stage it happened in.
//
// The central guarantee: ResultReject is only ever returned when an
// Access-Reject was actually received. A failed TLS handshake, a timeout, or a
// tunnel torn down mid-exchange is never reported as the server rejecting the
// credentials or certificate we presented, because the exchange does not prove
// that.
func (c *Collector) Classify(err error) (Result, Stage) {
	if c == nil {
		if err == nil {
			return ResultAccept, StageRadiusResponse
		}
		return ResultProtocolError, StageConfig
	}

	c.mu.Lock()
	ran := c.ran
	var (
		stage      = StageConfig
		sawReject  bool
		mismatches int
	)
	if a := c.cur; a != nil {
		if a.hasStage {
			stage = a.stage
		}
		sawReject = a.sawReject
		mismatches = a.idMismatch
	}
	c.mu.Unlock()

	if err == nil {
		return ResultAccept, stage
	}
	// Nothing reached the network, so this is our own misconfiguration rather
	// than anything observed about the server.
	if !ran {
		return ResultConfigError, StageConfig
	}

	var se *StageError
	if errors.As(err, &se) {
		result := se.Result
		if se.Stage != "" {
			stage = se.Stage
		}
		switch {
		case result == ResultReject && !sawReject:
			// The site claimed a rejection but no Access-Reject was observed,
			// so we only know the response was unusable.
			result = ResultProtocolError
		case result == ResultTimeout && mismatches > 0:
			// Something did answer, it just did not answer this request.
			result = ResultProtocolError
		}
		return result, stage
	}

	if sawReject {
		return ResultReject, stage
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		if mismatches > 0 {
			return ResultProtocolError, stage
		}
		return ResultTimeout, stage
	}
	return ResultProtocolError, stage
}
