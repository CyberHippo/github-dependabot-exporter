package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)


func TestGetenv(t *testing.T) {
	// Test when environment variable is set
	os.Setenv("FOO", "bar")
	val := getenv("FOO", "fallback")
	assert.Equal(t, "bar", val)

	// Test when environment variable is not set
	os.Unsetenv("FOO")
	val = getenv("FOO", "fallback")
	assert.Equal(t, "fallback", val)

	// Test when environment variable is set to empty string
	os.Setenv("FOO", "")
	val = getenv("FOO", "fallback")
	assert.Equal(t, "fallback", val)
}
