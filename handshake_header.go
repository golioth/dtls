package dtls

import (
	"encoding/binary"

	"github.com/pion/dtls/v2/internal/util"
	handshakePkg "github.com/pion/dtls/v2/pkg/protocol/handshake"
)

// msg_len for Handshake messages assumes an extra 12 bytes for
// sequence, fragment and version information
const handshakeHeaderLength = 12

type handshakeHeader struct {
	handshakeType   handshakePkg.Type
	length          uint32 // uint24 in spec
	messageSequence uint16
	fragmentOffset  uint32 // uint24 in spec
	fragmentLength  uint32 // uint24 in spec
}

func (h *handshakeHeader) Marshal() ([]byte, error) {
	out := make([]byte, handshakeMessageHeaderLength)

	out[0] = byte(h.handshakeType)
	util.PutBigEndianUint24(out[1:], h.length)
	binary.BigEndian.PutUint16(out[4:], h.messageSequence)
	util.PutBigEndianUint24(out[6:], h.fragmentOffset)
	util.PutBigEndianUint24(out[9:], h.fragmentLength)
	return out, nil
}

func (h *handshakeHeader) Unmarshal(data []byte) error {
	if len(data) < handshakeHeaderLength {
		return errBufferTooSmall
	}

	h.handshakeType = handshakePkg.Type(data[0])
	h.length = util.BigEndianUint24(data[1:])
	h.messageSequence = binary.BigEndian.Uint16(data[4:])
	h.fragmentOffset = util.BigEndianUint24(data[6:])
	h.fragmentLength = util.BigEndianUint24(data[9:])
	return nil
}
