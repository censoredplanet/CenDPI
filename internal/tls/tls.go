package tls

import (
    "crypto/rand"
    "encoding/binary"
	"encoding/hex"
    "fmt"
    "io"
)

type ClientHelloConfig struct {
    SNI          	 string // for the SNI extension
    ChVersion 		 string // 4 hex digits, e.g. "0303" or "0304"
}

type TLSRecordType string

const (
    PayloadClientHello   TLSRecordType = "clienthello"
    PayloadHelloRequest  TLSRecordType = "hello_request" 
    PayloadEmptyHandshake TLSRecordType = "empty_handshake"
    PayloadEmptyRecord   TLSRecordType = "empty_record"
    PayloadAlertWarning  TLSRecordType = "alert_warning"
)

type TLSRecordConfig struct {
    ContentType    byte
    RecordVersion  [2]byte
    PayloadType    TLSRecordType
    Offset         int
    Length         int
    AlertReasonHex string // if PayloadType=alert_warning, a 2-hex-digit reason (1 byte)
}

// TLSConfig is the top-level config.
type TLSConfig struct {
    ClientHelloConfig 	ClientHelloConfig
    Records 			[]TLSRecordConfig // The list of records to produce
}

func BuildTLS(cfg *TLSConfig) ([]byte, error) {
    // Build the clienthello upfront, so we can slice from it if needed.
    clientHelloPayload, err := buildClientHello(cfg.ClientHelloConfig)
    if err != nil {
        return nil, fmt.Errorf("error building clientHello: %v", err)
    }

    var finalBytes []byte

    // For each record config, build the payload, then wrap with BuildTLSRecord(), append to finalBytes
    for i, rec := range cfg.Records {
        // get the raw payload for this record
        payload, err := getRecordPayload(rec, clientHelloPayload)
        if err != nil {
            return nil, fmt.Errorf("record %d: %w", i, err)
        }
        // wrap in a TLS record
        recordBytes, err := buildTLSRecord(rec.ContentType, rec.RecordVersion, payload)
        if err != nil {
            return nil, fmt.Errorf("record %d: BuildTLSRecord error: %v", i, err)
        }
        finalBytes = append(finalBytes, recordBytes...)
    }
    return finalBytes, nil
}


func buildClientHello(cfg ClientHelloConfig) ([]byte, error) {

	sni, version := cfg.SNI, cfg.ChVersion
    if len(version) != 4 {
        return nil, fmt.Errorf("version must be exactly 4 hex digits (2 bytes), got length=%d", len(version))
    }
    verBytes, err := hex.DecodeString(version)
    if err != nil {
        return nil, fmt.Errorf("invalid hex version string '%s': %v", version, err)
    }
    if len(verBytes) != 2 {
        return nil, fmt.Errorf("expected 2 bytes after decoding version, got %d bytes", len(verBytes))
    }
    legacyVersion := [2]byte{verBytes[0], verBytes[1]}

    randomBytes := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
        return nil, fmt.Errorf("failed to get random for ClientHello random: %v", err)
    }
    sessionID := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, sessionID); err != nil {
        return nil, fmt.Errorf("failed to get random for session ID: %v", err)
    }

    cipherSuites := []uint16{
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xC02B, // ECDHE-ECDSA-AES128-GCM-SHA256
        0xC02C, // ECDHE-ECDSA-AES256-GCM-SHA384
        0xC02F, // ECDHE-RSA-AES128-GCM-SHA256
        0xC030, // ECDHE-RSA-AES256-GCM-SHA384
    }
    cipherSuitesBytes := make([]byte, 2*len(cipherSuites))
    for i, cs := range cipherSuites {
        binary.BigEndian.PutUint16(cipherSuitesBytes[i*2:], cs)
    }

    compressionMethods := []byte{0x00} // null

    // Extensions: (curl)
	// a) Supported Versions
    supportedVersionsExt := buildSupportedVersionsExtension()
	// b) Key Share
    keyShareExt, err := buildKeyShareExtension()
    if err != nil {
        return nil, err
    }
    // c) SNI
    sniExtension := buildServerNameExtension(sni)
	// d) EC Point Formats
    ecPointsExt := buildEcPointFormatsExtension()
	// e) Supported Groups
    supportedGroupsExt := buildSupportedGroupsExtension()
    // f) Signature Algorithms
    sigAlgsExt := buildSignatureAlgorithmsExtension()
    // g) ALPN
    alpnExt := buildAlpnExtension()

	var allExtensions []byte
	allExtensions = append(allExtensions, supportedVersionsExt...)
	allExtensions = append(allExtensions, keyShareExt...)
	allExtensions = append(allExtensions, sniExtension...)
	allExtensions = append(allExtensions, ecPointsExt...)
	allExtensions = append(allExtensions, supportedGroupsExt...)
	allExtensions = append(allExtensions, sigAlgsExt...)
	allExtensions = append(allExtensions, alpnExt...)
    extLen := len(allExtensions)

    // Build the body (excluding the initial 4-byte handshake header).
    var body []byte

    // legacy_version
    body = append(body, legacyVersion[:]...) 
    // random
    body = append(body, randomBytes...) 
    // session ID
    body = append(body, byte(len(sessionID))) // session_id length
    body = append(body, sessionID...) 
    // cipher_suites
    csLenBytes := make([]byte, 2)
    binary.BigEndian.PutUint16(csLenBytes, uint16(len(cipherSuitesBytes)))
    body = append(body, csLenBytes...)
    body = append(body, cipherSuitesBytes...)
    // compression_methods
    body = append(body, byte(len(compressionMethods)))
    body = append(body, compressionMethods...)
    // extensions
    extLenBytes := make([]byte, 2)
    binary.BigEndian.PutUint16(extLenBytes, uint16(extLen))
    body = append(body, extLenBytes...)
    body = append(body, allExtensions...)

	// putting all together
	totalLen := len(body)
    if totalLen > 0xFFFFFF {
        return nil, fmt.Errorf("handshake body too large (>16MB)")
    }
    out := make([]byte, 4, 4+totalLen)
    out[0] = 0x01 // HandshakeType = client_hello
    // 3-byte length
    out[1] = byte(totalLen >> 16)
    out[2] = byte(totalLen >> 8)
    out[3] = byte(totalLen)

    out = append(out, body...)
    return out, nil
}

func buildServerNameExtension(sni string) []byte {
    hostnameBytes := []byte(sni)
    nameLen := len(hostnameBytes)

    // SNI list length = 1 (name_type) + 2 (name len) + nameLen
    sniListLen := 1 + 2 + nameLen
    extDataLen := 2 + sniListLen // 2 bytes for SNI list length + sniListLen

    out := make([]byte, 4+extDataLen) // 4 = extension_type(2) + extension_len(2)
    // extension type = 0x0000
    out[0] = 0x00
    out[1] = 0x00
    // extension length
    binary.BigEndian.PutUint16(out[2:4], uint16(extDataLen))
    // SNI list length
    binary.BigEndian.PutUint16(out[4:6], uint16(sniListLen))
    // name_type
    out[6] = 0x00
    // name length
    binary.BigEndian.PutUint16(out[7:9], uint16(nameLen))
    // name
    copy(out[9:], hostnameBytes)
    return out
}

func buildSupportedVersionsExtension() []byte {
	versions := []uint16{0x0304, 0x0303, 0x0302, 0x0301} // 1.3,1.2,1.1,1.0
    numVersions := len(versions)

    // Each version is 2 bytes
    body := make([]byte, 1+2*numVersions) // 1 byte for length, then pairs
    body[0] = byte(2 * numVersions)
    for i, v := range versions {
        offset := 1 + 2*i
        binary.BigEndian.PutUint16(body[offset:], v)
    }
    ext := make([]byte, 4+len(body))
    // ext type
    ext[0] = 0x00
    ext[1] = 0x2b
    // ext length
    binary.BigEndian.PutUint16(ext[2:4], uint16(len(body)))
    // data
    copy(ext[4:], body)
    return ext
}

func buildKeyShareExtension() ([]byte, error) {
    // x25519 = 0x001d
    group := uint16(0x001d)
    keyLen := 32
    key := make([]byte, keyLen)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        return nil, fmt.Errorf("failed to read random for key share: %v", err)
    }
    // KeyShareEntry:
    //   group(2) + key_exchange_length(2) + key_exchange_data(32)
    entryLen := 2 + 2 + keyLen
    entry := make([]byte, entryLen)
    binary.BigEndian.PutUint16(entry[0:2], group)
    binary.BigEndian.PutUint16(entry[2:4], uint16(keyLen))
    copy(entry[4:], key)

    // Then wrap it with 2 bytes for key_share_list_length
    ksListLen := make([]byte, 2)
    binary.BigEndian.PutUint16(ksListLen, uint16(entryLen))

    data := append(ksListLen, entry...) // now we have the KeyShareEntry list

    // extension header: type=0x0033, length=?
    ext := make([]byte, 4+len(data))
    ext[0] = 0x00
    ext[1] = 0x33
    binary.BigEndian.PutUint16(ext[2:4], uint16(len(data)))
    copy(ext[4:], data)
    return ext, nil
}

func buildSignatureAlgorithmsExtension() []byte {
    // Example set: (curl)
    sigAlgs := []uint16{
        0x0806,
		0x0601,
		0x0603,
		0x0805,
		0x0501,
		0x0503,
		0x0804,
		0x0401,
		0x0403,
		0x0201,
		0x0203,
    }
    sigAlgBytes := make([]byte, 2*len(sigAlgs))
    for i, alg := range sigAlgs {
        binary.BigEndian.PutUint16(sigAlgBytes[i*2:], alg)
    }

    salLen := uint16(len(sigAlgBytes))
    body := make([]byte, 2+salLen)
    // 2 bytes = length
    binary.BigEndian.PutUint16(body[0:2], salLen)
    copy(body[2:], sigAlgBytes)

    ext := make([]byte, 4+len(body))
    // extension_type = 0x000d
    ext[0] = 0x00
    ext[1] = 0x0d
    // extension_length
    binary.BigEndian.PutUint16(ext[2:4], uint16(len(body)))
    copy(ext[4:], body)

    return ext
}


func buildSupportedGroupsExtension() []byte {
	// Example set: (curl)
    groups := []uint16{
		0x001d,
		0x0017,
		0x0018,
		0x0019,
	}
    groupBytes := make([]byte, 2*len(groups))
    for i, grp := range groups {
        binary.BigEndian.PutUint16(groupBytes[i*2:], grp)
    }
    totalLen := uint16(len(groupBytes))
    body := make([]byte, 2+totalLen)
    // 2 bytes for length
    binary.BigEndian.PutUint16(body[0:2], totalLen)
    copy(body[2:], groupBytes)

    ext := make([]byte, 4+len(body))
    // extension_type = 0x000a
    ext[0] = 0x00
    ext[1] = 0x0a
    // extension_length
    binary.BigEndian.PutUint16(ext[2:4], uint16(len(body)))
    copy(ext[4:], body)
    return ext
}

func buildEcPointFormatsExtension() []byte {
    body := []byte{1, 0} // uncompressed
    ext := make([]byte, 4+len(body))
    ext[0] = 0x00
    ext[1] = 0x0b
    binary.BigEndian.PutUint16(ext[2:4], uint16(len(body)))
    copy(ext[4:], body)
    return ext
}

func buildAlpnExtension() []byte {
    // h2, http/1.1 (curl)
    protoH2 := []byte("h2")
    protoHttp := []byte("http/1.1")

    var alpnBody []byte
    // "h2"
    alpnBody = append(alpnBody, byte(len(protoH2)))
    alpnBody = append(alpnBody, protoH2...)
    // "http/1.1"
    alpnBody = append(alpnBody, byte(len(protoHttp)))
    alpnBody = append(alpnBody, protoHttp...)

    alpnLen := make([]byte, 2)
    binary.BigEndian.PutUint16(alpnLen, uint16(len(alpnBody)))
    extData := append(alpnLen, alpnBody...)

    ext := make([]byte, 4+len(extData))
    // extension type 0x0010
    ext[0] = 0x00
    ext[1] = 0x10
    // extension length
    binary.BigEndian.PutUint16(ext[2:4], uint16(len(extData)))
    copy(ext[4:], extData)
    return ext
}

// BuildHelloRequest returns the handshake message for "HelloRequest" (legacy).
func buildHelloRequest() []byte {
    //   byte 0:   handshake type (0x00 = hello_request)
    //   bytes1..3: 24-bit length field
    return []byte{0x00, 0x00, 0x00, 0x00}
}

func buildEmptyHandshake() []byte {
    // 0x01 = client_hello handshake type, length=0
    return []byte{0x01, 0x00, 0x00, 0x00}
}

func buildEmptyRecord() []byte {
    return []byte{}
}

func buildAlertWarning(reason string) ([]byte, error) {
	if len(reason) != 2 {
        return nil, fmt.Errorf("reason must be exactly 2 hex digits (1 byte), got length=%d", len(reason))
    }
    reasonBytes, err := hex.DecodeString(reason)
    if err != nil {
        return nil, fmt.Errorf("invalid hex reason string '%s': %v", reason, err)
    }
	return []byte{0x01, reasonBytes[0]}, nil
}

func buildTLSRecord(recordType byte, version [2]byte, payload []byte) ([]byte, error) {
    payloadLen := len(payload)
    if payloadLen > 0xFFFF {
        return nil, fmt.Errorf("payload too large for a single TLS record (%d bytes)", payloadLen)
    }

    record := make([]byte, 5+payloadLen)
    record[0] = recordType
    record[1] = version[0]
    record[2] = version[1]
    binary.BigEndian.PutUint16(record[3:5], uint16(payloadLen))
    copy(record[5:], payload)

    return record, nil
}

func getRecordPayload(rec TLSRecordConfig, clientHello []byte) ([]byte, error) {
    switch rec.PayloadType {
    case PayloadClientHello:
        // We'll slice the [Offset : Offset+Length]
        if rec.Offset < 0 || rec.Offset > len(clientHello) {
            return nil, fmt.Errorf("invalid offset %d for clienthello of length %d", rec.Offset, len(clientHello))
        }
        end := rec.Offset + rec.Length
        if rec.Length < 0 {
            end = len(clientHello) // until end
        }
        if end > len(clientHello) {
            return nil, fmt.Errorf("invalid end %d for clienthello of length %d", end, len(clientHello))
        }
        return clientHello[rec.Offset:end], nil

    case PayloadHelloRequest:
        return buildHelloRequest(), nil

    case PayloadEmptyHandshake:
        return buildEmptyHandshake(), nil

    case PayloadEmptyRecord:
        return buildEmptyRecord(), nil

    case PayloadAlertWarning:
        // interpret rec.AlertReasonHex or just default to "5a" => user_canceled
        reasonHex := rec.AlertReasonHex
        if reasonHex == "" {
            reasonHex = "5a" // user_canceled
        }
        alert, err := buildAlertWarning(reasonHex)
        if err != nil {
            return nil, fmt.Errorf("failed building alert: %v", err)
        }
        return alert, nil

    default:
        return nil, fmt.Errorf("unknown PayloadType: %s", rec.PayloadType)
    }
}