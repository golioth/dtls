package dtls

import handshakePkg "github.com/pion/dtls/v2/pkg/protocol/handshake"

type handshakeMessageServerHelloDone struct {
}

func (h handshakeMessageServerHelloDone) Type() handshakePkg.Type {
	return handshakePkg.TypeServerHelloDone
}

func (h *handshakeMessageServerHelloDone) Marshal() ([]byte, error) {
	return []byte{}, nil
}

func (h *handshakeMessageServerHelloDone) Unmarshal(data []byte) error {
	return nil
}
