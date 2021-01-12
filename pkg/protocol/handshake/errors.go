package handshake

import "errors"

// Typed errors
var (
	errBufferTooSmall           = errors.New("buffer is too small")
	errLengthMismatch           = errors.New("data length and declared length do not match")
	errInvalidClientKeyExchange = errors.New("unable to determine if ClientKeyExchange is a public key or PSK Identity")
)
