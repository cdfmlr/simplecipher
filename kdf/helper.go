package kdf

func recoverFromPanic(err *error) {
	if r := recover(); r != nil {
		*err = r.(error)
	}
}
