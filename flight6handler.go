package dtls

import (
	"context"

	handshakePkg "github.com/pion/dtls/v2/pkg/protocol/handshake"
)

func flight6Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert, error) {
	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence-1,
		handshakeCachePullRule{handshakePkg.TypeFinished, cfg.initialEpoch + 1, true, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok = msgs[handshakePkg.TypeFinished].(*handshakeMessageFinished); !ok {
		return 0, &alert{alertLevelFatal, alertInternalError}, nil
	}

	// Other party retransmitted the last flight.
	return flight6, nil, nil
}

func flight6Generate(c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert, error) {
	var pkts []*packet

	pkts = append(pkts,
		&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &changeCipherSpec{},
			},
		})

	if len(state.localVerifyData) == 0 {
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{handshakePkg.TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshakePkg.TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakePkg.TypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakePkg.TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakePkg.TypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakePkg.TypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakePkg.TypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshakePkg.TypeClientKeyExchange, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshakePkg.TypeCertificateVerify, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshakePkg.TypeFinished, cfg.initialEpoch + 1, true, false},
		)

		var err error
		state.localVerifyData, err = prfVerifyDataServer(state.masterSecret, plainText, state.cipherSuite.hashFunc())
		if err != nil {
			return nil, &alert{alertLevelFatal, alertInternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
					epoch:           1,
				},
				content: &handshake{
					handshakeMessage: &handshakeMessageFinished{
						verifyData: state.localVerifyData,
					},
				},
			},
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		},
	)
	return pkts, nil, nil
}
