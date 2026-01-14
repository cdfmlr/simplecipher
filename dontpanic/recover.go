package dontpanic

import (
	"errors"
	"fmt"
)

// RecoverTo recovers from a panic and sets a ErrPanic to the given pointer.
// if the panic value is an error, it will be wrapped,
// caller can use errors.Is to check the underlying error.
func RecoverTo(err *error) {
	if r := recover(); r != nil {
		// *err = fmt.Errorf("%w: %v", ErrPanic, r)
		switch e := r.(type) {
		case error:
			*err = fmt.Errorf("%w: %w", ErrPanic, e)
		default:
			*err = fmt.Errorf("%w: %v", ErrPanic, r)
		}
	}
}

var ErrPanic = errors.New("recovered from panic")
