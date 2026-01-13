package kdf

import "fmt"

func recoverFromPanic(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%w: %v", ErrPanic, r)
	}
}
