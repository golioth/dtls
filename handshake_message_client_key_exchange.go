package dtls

import (
	"encoding/binary"

	handshakePkg "github.com/pion/dtls/v2/pkg/protocol/handshake"
)

type handshakeMessageClientKeyExchange struct {
	identityHint []byte
	publicKey    []byte
}

func (h handshakeMessageClientKeyExchange) Type() handshakePkg.Type {
	return handshakePkg.TypeClientKeyExchange
}

func (h *handshakeMessageClientKeyExchange) Marshal() ([]byte, error) {
	switch {
	case (h.identityHint != nil && h.publicKey != nil) || (h.identityHint == nil && h.publicKey == nil):
		return nil, errInvalidClientKeyExchange
	case h.publicKey != nil:
		return append([]byte{byte(len(h.publicKey))}, h.publicKey...), nil
	default:
		out := append([]byte{0x00, 0x00}, h.identityHint...)
		binary.BigEndian.PutUint16(out, uint16(len(out)-2))
		return out, nil
	}
}

func (h *handshakeMessageClientKeyExchange) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errBufferTooSmall
	}

	// If parsed as PSK return early and only populate PSK Identity Hint
	if pskLength := binary.BigEndian.Uint16(data); len(data) == int(pskLength+2) {
		h.identityHint = append([]byte{}, data[2:]...)
		return nil
	}

	if publicKeyLength := int(data[0]); len(data) != publicKeyLength+1 {
		return errBufferTooSmall
	}

	h.publicKey = append([]byte{}, data[1:]...)
	return nil
}
