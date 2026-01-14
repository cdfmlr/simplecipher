package dontpanic

import (
	"errors"
	"testing"
)

// TestRecoverTo_withError tests that RecoverTo properly catches a panic from an error
func TestRecoverTo_withError(t *testing.T) {
	var err error

	func() {
		defer RecoverTo(&err)
		panic(errors.New("test error"))
	}()

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Check that the error wraps ErrPanic
	if !errors.Is(err, ErrPanic) {
		t.Errorf("expected error to wrap ErrPanic, got: %v", err)
	}
}

// TestRecoverTo_withStringPanic tests that RecoverTo properly catches a panic from a string
func TestRecoverTo_withStringPanic(t *testing.T) {
	var err error

	func() {
		defer RecoverTo(&err)
		panic("string panic message")
	}()

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Check that the error wraps ErrPanic
	if !errors.Is(err, ErrPanic) {
		t.Errorf("expected error to wrap ErrPanic, got: %v", err)
	}
}

// TestRecoverTo_withIntPanic tests that RecoverTo properly catches a panic from an int
func TestRecoverTo_withIntPanic(t *testing.T) {
	var err error

	func() {
		defer RecoverTo(&err)
		panic(42)
	}()

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Check that the error wraps ErrPanic
	if !errors.Is(err, ErrPanic) {
		t.Errorf("expected error to wrap ErrPanic, got: %v", err)
	}
}

// TestRecoverTo_withNoPanic tests that RecoverTo does nothing when there's no panic
func TestRecoverTo_withNoPanic(t *testing.T) {
	var err error

	func() {
		defer RecoverTo(&err)
		// No panic here
	}()

	if err != nil {
		t.Errorf("expected no error when there's no panic, got: %v", err)
	}
}

// TestRecoverErrorWrapping tests that the original error can be retrieved using errors.As
func TestRecoverErrorWrapping(t *testing.T) {
	customErr := errors.New("custom error")
	var err error

	func() {
		defer RecoverTo(&err)
		panic(customErr)
	}()

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Check that we can retrieve the original error
	if !errors.Is(err, customErr) {
		t.Errorf("expected original error to be wrapped, got: %v", err)
	}
}

// TestRecoverMultipleLevels tests that RecoverTo works with nested defers
func TestRecoverMultipleLevels(t *testing.T) {
	var err error

	func() {
		defer RecoverTo(&err)
		func() {
			defer RecoverTo(&err)
			panic("nested panic")
		}()
	}()

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrPanic) {
		t.Errorf("expected error to wrap ErrPanic, got: %v", err)
	}
}

// TestErrPanicVariable tests that ErrPanic is properly defined
func TestErrPanicVariable(t *testing.T) {
	if ErrPanic == nil {
		t.Fatal("ErrPanic should not be nil")
	}

	if ErrPanic.Error() != "recovered from panic" {
		t.Errorf("expected ErrPanic message to be 'recovered from panic', got: %s", ErrPanic.Error())
	}
}
