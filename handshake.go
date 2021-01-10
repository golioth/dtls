package dtls

import (
	"github.com/pion/dtls/v2/internal/util"
	handshakePkg "github.com/pion/dtls/v2/pkg/protocol/handshake"
)

const (
	// msg_len for Handshake messages assumes an extra 12 bytes for
	// sequence, fragment and version information
	handshakeMessageHeaderLength = 12
)

type handshakeMessage interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error

	Type() handshakePkg.Type
}

// The handshake protocol is responsible for selecting a cipher spec and
// generating a master secret, which together comprise the primary
// cryptographic parameters associated with a secure session.  The
// handshake protocol can also optionally authenticate parties who have
// certificates signed by a trusted certificate authority.
// https://tools.ietf.org/html/rfc5246#section-7.3
type handshake struct {
	handshakeHeader  handshakeHeader
	handshakeMessage handshakeMessage
}

func (h handshake) contentType() contentType {
	return contentTypeHandshake
}

func (h *handshake) Marshal() ([]byte, error) {
	if h.handshakeMessage == nil {
		return nil, errHandshakeMessageUnset
	} else if h.handshakeHeader.fragmentOffset != 0 {
		return nil, errUnableToMarshalFragmented
	}

	msg, err := h.handshakeMessage.Marshal()
	if err != nil {
		return nil, err
	}

	h.handshakeHeader.length = uint32(len(msg))
	h.handshakeHeader.fragmentLength = h.handshakeHeader.length
	h.handshakeHeader.handshakeType = h.handshakeMessage.Type()
	header, err := h.handshakeHeader.Marshal()
	if err != nil {
		return nil, err
	}

	return append(header, msg...), nil
}

func (h *handshake) Unmarshal(data []byte) error {
	if err := h.handshakeHeader.Unmarshal(data); err != nil {
		return err
	}

	reportedLen := util.BigEndianUint24(data[1:])
	if uint32(len(data)-handshakeMessageHeaderLength) != reportedLen {
		return errLengthMismatch
	} else if reportedLen != h.handshakeHeader.fragmentLength {
		return errLengthMismatch
	}

	switch handshakePkg.Type(data[0]) {
	case handshakePkg.TypeHelloRequest:
		return errNotImplemented
	case handshakePkg.TypeClientHello:
		h.handshakeMessage = &handshakeMessageClientHello{}
	case handshakePkg.TypeHelloVerifyRequest:
		h.handshakeMessage = &handshakeMessageHelloVerifyRequest{}
	case handshakePkg.TypeServerHello:
		h.handshakeMessage = &handshakeMessageServerHello{}
	case handshakePkg.TypeCertificate:
		h.handshakeMessage = &handshakePkg.MessageCertificate{}
	case handshakePkg.TypeServerKeyExchange:
		h.handshakeMessage = &handshakeMessageServerKeyExchange{}
	case handshakePkg.TypeCertificateRequest:
		h.handshakeMessage = &handshakeMessageCertificateRequest{}
	case handshakePkg.TypeServerHelloDone:
		h.handshakeMessage = &handshakeMessageServerHelloDone{}
	case handshakePkg.TypeClientKeyExchange:
		h.handshakeMessage = &handshakeMessageClientKeyExchange{}
	case handshakePkg.TypeFinished:
		h.handshakeMessage = &handshakeMessageFinished{}
	case handshakePkg.TypeCertificateVerify:
		h.handshakeMessage = &handshakeMessageCertificateVerify{}
	default:
		return errNotImplemented
	}
	return h.handshakeMessage.Unmarshal(data[handshakeMessageHeaderLength:])
}
