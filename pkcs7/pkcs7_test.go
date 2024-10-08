// Fork from https://github.com/rclone/rclone/blob/8d78768aaad75e8ff634981458990a66820093fd/backend/crypt/pkcs7/pkcs7.go
// MIT License
package pkcs7

import (
	"fmt"
	"reflect"
	"testing"
)

func TestPad(t *testing.T) {
	assert := &assert{}

	for _, test := range []struct {
		n        int
		in       string
		expected string
	}{
		{8, "", "\x08\x08\x08\x08\x08\x08\x08\x08"},
		{8, "1", "1\x07\x07\x07\x07\x07\x07\x07"},
		{8, "12", "12\x06\x06\x06\x06\x06\x06"},
		{8, "123", "123\x05\x05\x05\x05\x05"},
		{8, "1234", "1234\x04\x04\x04\x04"},
		{8, "12345", "12345\x03\x03\x03"},
		{8, "123456", "123456\x02\x02"},
		{8, "1234567", "1234567\x01"},
		{8, "abcdefgh", "abcdefgh\x08\x08\x08\x08\x08\x08\x08\x08"},
		{8, "abcdefgh1", "abcdefgh1\x07\x07\x07\x07\x07\x07\x07"},
		{8, "abcdefgh12", "abcdefgh12\x06\x06\x06\x06\x06\x06"},
		{8, "abcdefgh123", "abcdefgh123\x05\x05\x05\x05\x05"},
		{8, "abcdefgh1234", "abcdefgh1234\x04\x04\x04\x04"},
		{8, "abcdefgh12345", "abcdefgh12345\x03\x03\x03"},
		{8, "abcdefgh123456", "abcdefgh123456\x02\x02"},
		{8, "abcdefgh1234567", "abcdefgh1234567\x01"},
		{8, "abcdefgh12345678", "abcdefgh12345678\x08\x08\x08\x08\x08\x08\x08\x08"},
		{16, "", "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"},
		{16, "a", "a\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f"},
	} {
		actual := Pad(test.n, []byte(test.in))
		assert.Equal(t, test.expected, string(actual), fmt.Sprintf("Pad %d %q", test.n, test.in))
		recovered, err := Unpad(test.n, actual)
		assert.NoError(t, err)
		assert.Equal(t, []byte(test.in), recovered, fmt.Sprintf("Unpad %d %q", test.n, test.in))
	}
	assert.Panics(t, func() { Pad(1, []byte("")) }, "bad multiple")
	assert.Panics(t, func() { Pad(256, []byte("")) }, "bad multiple")
}

func TestUnpad(t *testing.T) {
	assert := &assert{}

	// We've tested the OK decoding in TestPad, now test the error cases
	for _, test := range []struct {
		n   int
		in  string
		err error
	}{
		{8, "", ErrorPaddingNotFound},
		{8, "1", ErrorPaddingNotAMultiple},
		{8, "12", ErrorPaddingNotAMultiple},
		{8, "123", ErrorPaddingNotAMultiple},
		{8, "1234", ErrorPaddingNotAMultiple},
		{8, "12345", ErrorPaddingNotAMultiple},
		{8, "123456", ErrorPaddingNotAMultiple},
		{8, "1234567", ErrorPaddingNotAMultiple},
		{8, "1234567\xFF", ErrorPaddingTooLong},
		{8, "1234567\x09", ErrorPaddingTooLong},
		{8, "1234567\x00", ErrorPaddingTooShort},
		{8, "123456\x01\x02", ErrorPaddingNotAllTheSame},
		{8, "\x07\x08\x08\x08\x08\x08\x08\x08", ErrorPaddingNotAllTheSame},
	} {
		result, actualErr := Unpad(test.n, []byte(test.in))
		assert.Equal(t, test.err, actualErr, fmt.Sprintf("Unpad %d %q", test.n, test.in))
		assert.Equal(t, result, []byte(nil))
	}
	assert.Panics(t, func() { _, _ = Unpad(1, []byte("")) }, "bad multiple")
	assert.Panics(t, func() { _, _ = Unpad(256, []byte("")) }, "bad multiple")
}

// assert is a test helper in replacement of "github.com/stretchr/testify/assert"
type assert struct{}

func (a *assert) Equal(t *testing.T, expected, actual interface{}, msgAndArgs ...interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf(fmt.Sprintf("Not equal: expected %v, actual %v", expected, actual))
	}
}

func (a *assert) NoError(t *testing.T, err error, msgAndArgs ...interface{}) {
	if err != nil {
		t.Errorf(fmt.Sprintf("Unexpected error: %v", err))
	}
}

func (a *assert) Panics(t *testing.T, f func(), msgAndArgs ...interface{}) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf(fmt.Sprintf("Function did not panic"))
		}
	}()
	f()
}
