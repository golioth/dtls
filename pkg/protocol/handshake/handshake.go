// Package handshake provides the DTLS wire protocol for handshakes
package handshake

// Type is the unique identifier for each handshake message
// https://tools.ietf.org/html/rfc5246#section-7.4
type Type uint8

// Types of DTLS Handshake messages we know about
const (
	TypeHelloRequest       Type = 0
	TypeClientHello        Type = 1
	TypeServerHello        Type = 2
	TypeHelloVerifyRequest Type = 3
	TypeCertificate        Type = 11
	TypeServerKeyExchange  Type = 12
	TypeCertificateRequest Type = 13
	TypeServerHelloDone    Type = 14
	TypeCertificateVerify  Type = 15
	TypeClientKeyExchange  Type = 16
	TypeFinished           Type = 20
)

// String returns the string representation of this type
func (t Type) String() string {
	switch t {
	case TypeHelloRequest:
		return "HelloRequest"
	case TypeClientHello:
		return "ClientHello"
	case TypeServerHello:
		return "ServerHello"
	case TypeHelloVerifyRequest:
		return "HelloVerifyRequest"
	case TypeCertificate:
		return "TypeCertificate"
	case TypeServerKeyExchange:
		return "ServerKeyExchange"
	case TypeCertificateRequest:
		return "CertificateRequest"
	case TypeServerHelloDone:
		return "ServerHelloDone"
	case TypeCertificateVerify:
		return "CertificateVerify"
	case TypeClientKeyExchange:
		return "ClientKeyExchange"
	case TypeFinished:
		return "Finished"
	}
	return ""
}
