package dtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"

	handshakePkg "github.com/pion/dtls/v2/pkg/protocol/handshake"
)

func flight5Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert, error) {
	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence,
		handshakeCachePullRule{handshakePkg.TypeFinished, cfg.initialEpoch + 1, false, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	var finished *handshakeMessageFinished
	if finished, ok = msgs[handshakePkg.TypeFinished].(*handshakeMessageFinished); !ok {
		return 0, &alert{alertLevelFatal, alertInternalError}, nil
	}
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

	expectedVerifyData, err := prfVerifyDataServer(state.masterSecret, plainText, state.cipherSuite.hashFunc())
	if err != nil {
		return 0, &alert{alertLevelFatal, alertInternalError}, err
	}
	if !bytes.Equal(expectedVerifyData, finished.verifyData) {
		return 0, &alert{alertLevelFatal, alertHandshakeFailure}, errVerifyDataMismatch
	}

	return flight5, nil, nil
}

func flight5Generate(c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert, error) { //nolint:gocognit
	var certBytes [][]byte
	var privateKey crypto.PrivateKey
	if len(cfg.localCertificates) > 0 {
		certificate, err := cfg.getCertificate(cfg.serverName)
		if err != nil {
			return nil, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}
		certBytes = certificate.Certificate
		privateKey = certificate.PrivateKey
	}

	var pkts []*packet

	if state.remoteRequestedCertificate {
		pkts = append(pkts,
			&packet{
				record: &recordLayer{
					recordLayerHeader: recordLayerHeader{
						protocolVersion: protocolVersion1_2,
					},
					content: &handshake{
						handshakeMessage: &handshakePkg.MessageCertificate{
							Certificate: certBytes,
						},
					},
				},
			})
	}

	clientKeyExchange := &handshakePkg.MessageClientKeyExchange{}
	if cfg.localPSKCallback == nil {
		clientKeyExchange.PublicKey = state.localKeypair.publicKey
	} else {
		clientKeyExchange.IdentityHint = cfg.localPSKIdentityHint
	}

	pkts = append(pkts,
		&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeMessage: clientKeyExchange,
				},
			},
		})

	serverKeyExchangeData := cache.pullAndMerge(
		handshakeCachePullRule{handshakePkg.TypeServerKeyExchange, cfg.initialEpoch, false, false},
	)

	serverKeyExchange := &handshakeMessageServerKeyExchange{}

	// handshakeMessageServerKeyExchange is optional for PSK
	if len(serverKeyExchangeData) == 0 {
		alertPtr, err := handleServerKeyExchange(c, state, cfg, &handshakeMessageServerKeyExchange{})
		if err != nil {
			return nil, alertPtr, err
		}
	} else {
		rawHandshake := &handshake{}
		err := rawHandshake.Unmarshal(serverKeyExchangeData)
		if err != nil {
			return nil, &alert{alertLevelFatal, alertUnexpectedMessage}, err
		}

		switch h := rawHandshake.handshakeMessage.(type) {
		case *handshakeMessageServerKeyExchange:
			serverKeyExchange = h
		default:
			return nil, &alert{alertLevelFatal, alertUnexpectedMessage}, errInvalidContentType
		}
	}

	// Append not-yet-sent packets
	merged := []byte{}
	seqPred := uint16(state.handshakeSendSequence)
	for _, p := range pkts {
		h, ok := p.record.content.(*handshake)
		if !ok {
			return nil, &alert{alertLevelFatal, alertInternalError}, errInvalidContentType
		}
		h.handshakeHeader.messageSequence = seqPred
		seqPred++
		raw, err := h.Marshal()
		if err != nil {
			return nil, &alert{alertLevelFatal, alertInternalError}, err
		}
		merged = append(merged, raw...)
	}

	if alertPtr, err := initalizeCipherSuite(state, cache, cfg, serverKeyExchange, merged); err != nil {
		return nil, alertPtr, err
	}

	// If the client has sent a certificate with signing ability, a digitally-signed
	// CertificateVerify message is sent to explicitly verify possession of the
	// private key in the certificate.
	if state.remoteRequestedCertificate && len(cfg.localCertificates) > 0 {
		plainText := append(cache.pullAndMerge(
			handshakeCachePullRule{handshakePkg.TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshakePkg.TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakePkg.TypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakePkg.TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakePkg.TypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakePkg.TypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakePkg.TypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshakePkg.TypeClientKeyExchange, cfg.initialEpoch, true, false},
		), merged...)

		// Find compatible signature scheme
		signatureHashAlgo, err := selectSignatureScheme(cfg.localSignatureSchemes, privateKey)
		if err != nil {
			return nil, &alert{alertLevelFatal, alertInsufficientSecurity}, err
		}

		certVerify, err := generateCertificateVerify(plainText, privateKey, signatureHashAlgo.hash)
		if err != nil {
			return nil, &alert{alertLevelFatal, alertInternalError}, err
		}
		state.localCertificatesVerify = certVerify

		p := &packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeMessage: &handshakeMessageCertificateVerify{
						hashAlgorithm:      signatureHashAlgo.hash,
						signatureAlgorithm: signatureHashAlgo.signature,
						signature:          state.localCertificatesVerify,
					},
				},
			},
		}
		pkts = append(pkts, p)

		h, ok := p.record.content.(*handshake)
		if !ok {
			return nil, &alert{alertLevelFatal, alertInternalError}, errInvalidContentType
		}
		h.handshakeHeader.messageSequence = seqPred
		// seqPred++ // this is the last use of seqPred
		raw, err := h.Marshal()
		if err != nil {
			return nil, &alert{alertLevelFatal, alertInternalError}, err
		}
		merged = append(merged, raw...)
	}

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
		state.localVerifyData, err = prfVerifyDataClient(state.masterSecret, append(plainText, merged...), state.cipherSuite.hashFunc())
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
		})

	return pkts, nil, nil
}

func initalizeCipherSuite(state *State, cache *handshakeCache, cfg *handshakeConfig, h *handshakeMessageServerKeyExchange, sendingPlainText []byte) (*alert, error) { //nolint:gocognit
	if state.cipherSuite.isInitialized() {
		return nil, nil
	}

	clientRandom := state.localRandom.marshalFixed()
	serverRandom := state.remoteRandom.marshalFixed()

	var err error

	if state.extendedMasterSecret {
		var sessionHash []byte
		sessionHash, err = cache.sessionHash(state.cipherSuite.hashFunc(), cfg.initialEpoch, sendingPlainText)
		if err != nil {
			return &alert{alertLevelFatal, alertInternalError}, err
		}

		state.masterSecret, err = prfExtendedMasterSecret(state.preMasterSecret, sessionHash, state.cipherSuite.hashFunc())
		if err != nil {
			return &alert{alertLevelFatal, alertIllegalParameter}, err
		}
	} else {
		state.masterSecret, err = prfMasterSecret(state.preMasterSecret, clientRandom[:], serverRandom[:], state.cipherSuite.hashFunc())
		if err != nil {
			return &alert{alertLevelFatal, alertInternalError}, err
		}
	}

	if cfg.localPSKCallback == nil {
		// Verify that the pair of hash algorithm and signiture is listed.
		var validSignatureScheme bool
		for _, ss := range cfg.localSignatureSchemes {
			if ss.hash == h.hashAlgorithm && ss.signature == h.signatureAlgorithm {
				validSignatureScheme = true
				break
			}
		}
		if !validSignatureScheme {
			return &alert{alertLevelFatal, alertInsufficientSecurity}, errNoAvailableSignatureSchemes
		}

		expectedMsg := valueKeyMessage(clientRandom[:], serverRandom[:], h.publicKey, h.namedCurve)
		if err = verifyKeySignature(expectedMsg, h.signature, h.hashAlgorithm, state.PeerCertificates); err != nil {
			return &alert{alertLevelFatal, alertBadCertificate}, err
		}
		var chains [][]*x509.Certificate
		if !cfg.insecureSkipVerify {
			if chains, err = verifyServerCert(state.PeerCertificates, cfg.rootCAs, cfg.serverName); err != nil {
				return &alert{alertLevelFatal, alertBadCertificate}, err
			}
		}
		if cfg.verifyPeerCertificate != nil {
			if err = cfg.verifyPeerCertificate(state.PeerCertificates, chains); err != nil {
				return &alert{alertLevelFatal, alertBadCertificate}, err
			}
		}
	}

	if err = state.cipherSuite.init(state.masterSecret, clientRandom[:], serverRandom[:], true); err != nil {
		return &alert{alertLevelFatal, alertInternalError}, err
	}
	return nil, nil
}
