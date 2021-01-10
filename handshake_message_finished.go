package dtls

import handshakePkg "github.com/pion/dtls/v2/pkg/protocol/handshake"

type handshakeMessageFinished struct {
	verifyData []byte
}

func (h handshakeMessageFinished) Type() handshakePkg.Type {
	return handshakePkg.TypeFinished
}

func (h *handshakeMessageFinished) Marshal() ([]byte, error) {
	return append([]byte{}, h.verifyData...), nil
}

func (h *handshakeMessageFinished) Unmarshal(data []byte) error {
	h.verifyData = append([]byte{}, data...)
	return nil
}
