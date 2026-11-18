/*
Copyright © 2025

Typed error wrapper that carries where a failure happened and what it means.
*/
package metrics

// StageError annotates an error with the stage it occurred in and the result
// it implies. Classification prefers this over inspecting error strings, which
// would rot the moment an upstream message is reworded.
//
// A StageError claiming ResultReject is only honored when an Access-Reject was
// actually observed on the wire; see Classify.
type StageError struct {
	Stage  Stage
	Result Result
	Err    error
}

func (e *StageError) Error() string {
	if e.Err == nil {
		return string(e.Result)
	}
	return e.Err.Error()
}

func (e *StageError) Unwrap() error {
	return e.Err
}

// Wrap annotates err, returning nil when err is nil so it can be used inline
// on a return path.
func Wrap(stage Stage, result Result, err error) error {
	if err == nil {
		return nil
	}
	return &StageError{Stage: stage, Result: result, Err: err}
}
