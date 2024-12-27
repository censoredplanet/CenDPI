package tls

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"log"
)

const (
	RecordHeaderTypeHandshake = 0x16
	ProtocolMajorVersion      = 0x03
	ProtocolMinorVersion0     = 0x01 // TLS 1.0
	ProtocolMinorVersion1     = 0x02 // TLS 1.1
	ProtocolMinorVersion2     = 0x03 // TLS 1.2
	ProtocolMinorVersion3     = 0x04 // TLS 1.3

	HandshakeHeaderMessageTypeClientHello = 0x01

	DNSHostnameNumber = 0x00
)

var (
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = []byte{0xcc, 0xa8}
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = []byte{0xcc, 0xa9}
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = []byte{0xc0, 0x2f}
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = []byte{0xc0, 0x30}
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = []byte{0xc0, 0x2b}
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = []byte{0xc0, 0x2c}
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            = []byte{0xc0, 0x13}
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          = []byte{0xc0, 0x09}
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            = []byte{0xc0, 0x14}
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          = []byte{0xc0, 0x0a}
	TLS_RSA_WITH_AES_128_GCM_SHA256               = []byte{0x00, 0x9c}
	TLS_RSA_WITH_AES_256_GCM_SHA384               = []byte{0x00, 0x9d}
	TLS_RSA_WITH_AES_128_CBC_SHA                  = []byte{0x00, 0x2f}
	TLS_RSA_WITH_AES_256_CBC_SHA                  = []byte{0x00, 0x35}
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           = []byte{0xc0, 0x12}
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 = []byte{0x00, 0x0a}

	CompressionMethodNone = []byte{0x01, 0x00}

	ExtensionServernameNumber      = []byte{0x00, 0x00}
	ExtensionSupportedGroupsNumber = []byte{0x00, 0x0a}

	EllipticCurveX25519    = []byte{0x00, 0x1d}
	EllipticCurveSecp256r1 = []byte{0x00, 0x17}
	EllipticCurveSecp384r1 = []byte{0x00, 0x18}
	EllipticCurveSecp521r1 = []byte{0x00, 0x19}

	ExtensionSignatureAlgorithmsNumber = []byte{0x00, 0x0d}
	Signature_RSA_PKCS1_SHA256         = []byte{0x04, 0x01}
	Signature_ECDSA_SECP256r1_SHA256   = []byte{0x04, 0x03}
	Signature_RSA_PKCS1_SHA384         = []byte{0x05, 0x01}
	Signature_ECDSA_SECP256r1_SHA384   = []byte{0x05, 0x03}
	Signature_RSA_PKCS1_SHA512         = []byte{0x06, 0x01}
	Signature_ECDSA_SECP256r1_SHA512   = []byte{0x06, 0x03}
	Signature_RSA_PKCS1_SHA1           = []byte{0x02, 0x01}
	Signature_ECDSA_SHA1               = []byte{0x02, 0x03}

	RenegotiationInfoNumber = []byte{0xff, 0x01}
)

type TLSConfig struct {
	SNI []string
}

type TLSLayer struct {
	config *TLSConfig
}

func New(config *TLSConfig) *TLSLayer {
	return &TLSLayer{
		config: config,
	}
}

func (t *TLSLayer) ClienHello() ([]byte, error) {
	var clientHello, clientVersion, recordHeader, handshakeHeader, cipherSuites []byte
	var extensionServerName, extensionSupportedGroups, extensionSignatureAlgorithms, extensionRenegotiationInfo []byte

	// Renegotiation Info Extension
	extensionRenegotiationInfo = append(extensionRenegotiationInfo, RenegotiationInfoNumber...)
	extensionRenegotiationInfo = append(extensionRenegotiationInfo, []byte{0x00, 0x01}...)
	extensionRenegotiationInfo = append(extensionRenegotiationInfo, []byte{0x00}...)

	clientHello = append(clientHello, extensionRenegotiationInfo...)

	// Signature Algorithms Extension
	extensionSignatureAlgorithms = append(extensionSignatureAlgorithms, ExtensionSignatureAlgorithmsNumber...)
	// Total Length & Length of Algorithms
	extensionSignatureAlgorithms = append(extensionSignatureAlgorithms, []byte{0x00, 0x12}...)
	extensionSignatureAlgorithms = append(extensionSignatureAlgorithms, []byte{0x00, 0x10}...)

	extensionSignatureAlgorithms = append(extensionSignatureAlgorithms, Signature_RSA_PKCS1_SHA256...)
	extensionSignatureAlgorithms = append(extensionSignatureAlgorithms, Signature_ECDSA_SECP256r1_SHA256...)
	extensionSignatureAlgorithms = append(extensionSignatureAlgorithms, Signature_RSA_PKCS1_SHA384...)
	extensionSignatureAlgorithms = append(extensionSignatureAlgorithms, Signature_ECDSA_SECP256r1_SHA384...)
	extensionSignatureAlgorithms = append(extensionSignatureAlgorithms, Signature_RSA_PKCS1_SHA512...)
	extensionSignatureAlgorithms = append(extensionSignatureAlgorithms, Signature_ECDSA_SECP256r1_SHA512...)
	extensionSignatureAlgorithms = append(extensionSignatureAlgorithms, Signature_RSA_PKCS1_SHA1...)
	extensionSignatureAlgorithms = append(extensionSignatureAlgorithms, Signature_ECDSA_SHA1...)

	clientHello = append(extensionSignatureAlgorithms, clientHello...)

	// Supported Groups Extension
	extensionSupportedGroups = append(extensionSupportedGroups, ExtensionSupportedGroupsNumber...)
	// Total Length & Length of Curves List
	extensionSupportedGroups = append(extensionSupportedGroups, []byte{0x00, 0x0A}...)
	extensionSupportedGroups = append(extensionSupportedGroups, []byte{0x00, 0x08}...)
	// Cruves
	extensionSupportedGroups = append(extensionSupportedGroups, EllipticCurveX25519...)
	extensionSupportedGroups = append(extensionSupportedGroups, EllipticCurveSecp256r1...)
	extensionSupportedGroups = append(extensionSupportedGroups, EllipticCurveSecp384r1...)
	extensionSupportedGroups = append(extensionSupportedGroups, EllipticCurveSecp521r1...)

	clientHello = append(extensionSupportedGroups, clientHello...)

	// Server Name Extension
	for _, sni := range t.config.SNI {
		byteString := []byte(sni)
		extensionServerName = append(extensionServerName, byteString...)

		// length of DNS hostname bytes
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, uint16(len(sni)))
		extensionServerName = append(buf.Bytes(), extensionServerName...)
	}

	// 0x00 for DNS hostname type
	extensionServerName = append([]byte{0x00}, extensionServerName...)

	/*
		According to this issue (https://github.com/golang/go/issues/13671), reusing buffers can
		lead to inconsistant views.
	*/
	bufListLen := new(bytes.Buffer)
	binary.Write(bufListLen, binary.BigEndian, uint16(len(extensionServerName)))
	extensionServerName = append(bufListLen.Bytes(), extensionServerName...)

	bufExtensionLen := new(bytes.Buffer)
	binary.Write(bufExtensionLen, binary.BigEndian, uint16(len(extensionServerName)))
	extensionServerName = append(bufExtensionLen.Bytes(), extensionServerName...)

	extensionServerName = append(ExtensionServernameNumber, extensionServerName...)

	clientHello = append(extensionServerName, clientHello...)

	//Extension Length
	extensionLen := new(bytes.Buffer)
	binary.Write(extensionLen, binary.BigEndian, uint16(len(clientHello)))
	clientHello = append(extensionLen.Bytes(), clientHello...)

	// No Compression
	clientHello = append(CompressionMethodNone, clientHello...)

	// Cipher Suites
	cipherSuites = append(cipherSuites, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256...)
	cipherSuites = append(cipherSuites, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256...)
	cipherSuites = append(cipherSuites, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256...)

	cipherSuitesLen := new(bytes.Buffer)
	binary.Write(cipherSuitesLen, binary.BigEndian, uint16(len(cipherSuites)))
	cipherSuites = append(cipherSuitesLen.Bytes(), cipherSuites...)

	clientHello = append(cipherSuites, clientHello...)

	// Session ID
	clientHello = append([]byte{0x00}, clientHello...) // Session ID, if available, otherwise 0

	// Client Random
	clientRandom := make([]byte, 32)
	_, err := rand.Read(clientRandom)
	if err != nil {
		log.Fatal(err)
	}
	clientHello = append(clientRandom, clientHello...)

	clientVersion = append(clientVersion, ProtocolMajorVersion, ProtocolMinorVersion2)
	clientHello = append(clientVersion, clientHello...)

	// Handshake Header
	handshakeHeader = append(handshakeHeader, HandshakeHeaderMessageTypeClientHello)
	// calculate Bytes to follow
	bufHandshakeLen := new(bytes.Buffer)
	binary.Write(bufHandshakeLen, binary.BigEndian, uint32(len(clientHello)))
	lengthField := bufHandshakeLen.Bytes()[1:]
	handshakeHeader = append(handshakeHeader, lengthField...)

	clientHello = append(handshakeHeader, clientHello...)

	// Record Header

	/*
		According to https://tls12.xargs.org/#client-hello/annotated and Go's crypto/tls library:
		if vers == 0 {
			// Some TLS servers fail if the record version is
			// greater than TLS 1.0 for the initial ClientHello.
			vers = VersionTLS10
		}
	*/
	recordHeader = append(recordHeader, RecordHeaderTypeHandshake, ProtocolMajorVersion, ProtocolMinorVersion0)
	// calculate Bytes to follow
	bufRecordLen := new(bytes.Buffer)
	binary.Write(bufRecordLen, binary.BigEndian, uint16(len(clientHello)))
	recordHeader = append(recordHeader, bufRecordLen.Bytes()...)

	clientHello = append(recordHeader, clientHello...)

	return clientHello, nil
}
