package ptracer

import "fmt"

// TracerError implements error interface
type TracerError struct {
	pid int
	err error
}

func (e TracerError) Error() string {
	return fmt.Sprintf("caught error, pid: %d, err: %q", e.pid, e.err.Error())
}
