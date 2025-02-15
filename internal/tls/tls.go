package tls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"gopkg.in/yaml.v3"
)

type ClientHelloConfig struct {
	SNI        string // for the SNI extension
	ChVersion  string `yaml:"chVersion"`  // 4 hex digits, e.g. "0303" or "0304"
	PQKeyShare bool   `yaml:"pqKeyShare"` // whether to include a key share for post-quantum
}

const (
	PayloadClientHello    string = "clienthello"
	PayloadHelloRequest   string = "hello_request"
	PayloadEmptyHandshake string = "empty_handshake"
	PayloadEmptyRecord    string = "empty_record"
	PayloadAlertWarning   string = "alert_warning"
)

type TLSRecordConfig struct {
	ContentType    byte    `yaml:"-"`
	RecordVersion  [2]byte `yaml:"-"`
	PayloadType    string  `yaml:"payloadType"`
	Offset         int     `yaml:"offset"`
	Length         int     `yaml:"length"`
	AlertReasonHex string  `yaml:"alertReasonHex"` // if PayloadType=alert_warning, a 2-hex-digit reason (1 byte)
}

// TLSConfig is the top-level config.
type TLSConfig struct {
	ClientHelloConfig ClientHelloConfig `yaml:"clientHelloConfig"`
	Records           []TLSRecordConfig `yaml:"records"` // The list of records to produce
}

func (t *TLSRecordConfig) UnmarshalYAML(node *yaml.Node) error {
	type base TLSRecordConfig
	raw := struct {
		base          `yaml:",inline"`
		ContentType   string `yaml:"contentType"`
		RecordVersion string `yaml:"recordVersion"`
	}{}

	if err := node.Decode(&raw); err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(raw.base.PayloadType)) {
	case PayloadClientHello, PayloadHelloRequest, PayloadEmptyHandshake, PayloadEmptyRecord, PayloadAlertWarning:
		t.PayloadType = raw.base.PayloadType
	default:
		return fmt.Errorf("invalid tls payloadType: %s, specified in probe yaml configration file", raw.base.PayloadType)
	}

	contentTypeByte, err := strconv.ParseUint(raw.ContentType, 16, 8)
	if err != nil {
		return fmt.Errorf("invalid content type specified in the yaml configuration: %s", raw.ContentType)
	}
	recordVersion, err := hex.DecodeString(raw.RecordVersion)
	if err != nil || len(recordVersion) != 2 {
		return fmt.Errorf("invalid recordVersion '%s'", raw.RecordVersion)
	}

	*t = TLSRecordConfig(raw.base)
	t.ContentType = byte(contentTypeByte)
	copy(t.RecordVersion[:], recordVersion)

	return nil
}

const clientHelloRandomHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
const sessionIDHex = "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
const keyshareHex = "AFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFA0A1A2A3A4A5A6A7A8A9AAABACADAE"

// 1116 bytes of pq key
const pqkeyshareHex = "8d99a4b0f28d35fc3d18a5a655f2948969acd4210ded118bd7e7797ee3bfd917" +
	"0d80723237666ef70336804c361ea5a333c04d93b94a770b8e41374bd305cbd538b0076cb56c" +
	"721c0fd4779c42bcb26828c0e095ae9272f4bcac76b69e83d11cf12321bca801e39710c8630f" +
	"38918e7f499570724b5b76087b4197a98c1819e5bf24407ca4139a05e62bb6cb36b0b7c2ae16" +
	"17260416af32b95f578209f3b1ccc66ca5699751470d3f47ad663024b88827dad946416365bf" +
	"09461fb40f5526785f5949bb99843403393d962783fa26beb74fc80b6033e2adeab941df2b08" +
	"c0e94b70a7ac95c682774302d569a2b09c0b76b0a74b0c5b7676828d192a73d47c771519398" +
	"840d2eb20d3608ca7c4ab47006ed3710e0c8c32106a6b99d684a9a43ad91835977352fe39b0" +
	"9d7261f305826409d0660c315a54abb34b1330bc2923e0425977af6bcca805b74d81a241d0ac" +
	"222dfaa0127576d6b6365ac59cecd045d241403ab95e987cc655d3c125d360233859a0a86e80" +
	"9843a9385f4bfb0015e2619fc73c6636cc684575ed610c281717c8e89d72788194788bd1603b" +
	"bd5151d3706ce8951a1db2568f5ac9c1e92f7447460585ba46785488e8961fac47b6c3bbea64" +
	"0e58221a28d323d4558b70b72b24cc138147af82640b2af118abb8c46bba010f989baa729ca3" +
	"0c93630c07d88c7771321049f1b637245bd1b3bd3580a412fb0dc605cedff37d7e8bb7f5821d" +
	"82ab3c142a58d2232326784aa1281b21e8058d6a46778ba4893452830c00a7715578fa668c55" +
	"4a0883b0350cce3d03a63d268af5454421f43780b7596c6131f7e7a3e9e0cb29288bf809632c" +
	"9437097b107d37b7512b9660f755e39071f9f4a9d1ba162d7c473eb6a310ba8b6d773773bb0c" +
	"b60841ff4c4964801370f9358c491836a4a4e45c4ccf6a12cf447328a1320f2b9e622bb6532a" +
	"47129b0218c52271e139b8f7ce47a312e8a873e0900fe6d0c1078b380efb2c4c250200f389f6" +
	"264f3fb073a17a730f9c6eb1c7978c9c7573e71ceb7198e15909a476c9718b8c0b2c3f23e151" +
	"a3d659b4197a0adb206dc757f80b2fffe00bdd6b0ae4742fd0a468d7ca982de85b2dc12709f1" +
	"915ce144658375c3119d21e8640063b862a461af6774a7115e70226922f8573ef47066350fda" +
	"b336eb024a97d3c042d29135d92c009272ec21aa9d77c3ca15bca3ea30a249098cf790f167ab" +
	"ab748f35518575288f6b167f388936408a2583b99d4dba675b1102ffa45099c29c0565320608" +
	"38843bb2f485aa671796a6a9b1864bab49140308d2106fd4335ef0cab7d36398f20ea3501913" +
	"bc461acccd96f3ad6a797181b97f0f193c1e6101aa49497c4b3ad540babea8b67bc9bb55b931" +
	"f7212587a5a3d1ac5c7fda00c7f898758b7ac2517d907b4f78755a3615aaf45089ebe92be8f2" +
	"879177b47091820a1c2a0be7746b25976992b83f174764564c35b331c4e351473b3f42f665ca" +
	"17a29ca985d3f45f6905633168426404ac990b7cf6cc746458733f6446f2e5c5846198972b10" +
	"214889066c0884168a32521faeda37a82337538c17"

func BuildTLS(cfg *TLSConfig) ([]byte, error) {
	// Build the clienthello upfront, so we can slice from it if needed.
	clientHelloPayload, err := buildClientHello(cfg.ClientHelloConfig)
	if err != nil {
		return nil, fmt.Errorf("error building clientHello: %s", err.Error())
	}

	var finalBytes []byte

	// For each record config, build the payload, then wrap with BuildTLSRecord(), append to finalBytes
	for i, rec := range cfg.Records {
		// get the raw payload for this record
		payload, err := getRecordPayload(rec, clientHelloPayload)
		if err != nil {
			return nil, fmt.Errorf("record %d: %s", i, err.Error())
		}
		// wrap in a TLS record
		recordBytes, err := buildTLSRecord(rec.ContentType, rec.RecordVersion, payload)
		if err != nil {
			return nil, fmt.Errorf("record %d: BuildTLSRecord error: %s", i, err.Error())
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
		return nil, fmt.Errorf("invalid hex version string '%s': %s", version, err.Error())
	}
	if len(verBytes) != 2 {
		return nil, fmt.Errorf("expected 2 bytes after decoding version, got %d bytes", len(verBytes))
	}
	legacyVersion := [2]byte{verBytes[0], verBytes[1]}

	randomBytes, err := hex.DecodeString(clientHelloRandomHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode clientHelloRandomHex: %s", err.Error())
	}
	if len(randomBytes) != 32 {
		return nil, fmt.Errorf("clientHelloRandomHex must represent exactly 32 bytes")
	}

	sessionID, err := hex.DecodeString(sessionIDHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode sessionIDHex: %s", err.Error())
	}
	if len(sessionID) != 32 {
		return nil, fmt.Errorf("sessionIDHex must represent exactly 32 bytes")
	}

	cipherSuites := []uint16{
		0x1303,
		0x1302,
		0x1301,
		0xcca9,
		0xcca8,
		0xccaa,
		0xc030,
		0xc02c,
		0xc028,
		0xc024,
		0xc014,
		0xc00a,
		0x009f,
		0x006b,
		0x0039,
		//0xff85,
		0x00c4,
		0x0088,
		0x0081,
		0x009d,
		0x003d,
		0x0035,
		0x00c0,
		0x0084,
		0xc02f,
		0xc02b,
		0xc027,
		0xc023,
		0xc013,
		0xc009,
		0x009e,
		0x0067,
		0x0033,
		0x00be,
		0x0045,
		0x009c,
		0x003c,
		0x002f,
		0x00ba,
		0x0041,
		0xc011,
		0xc007,
		0x0005,
		0x0004,
		0xc012,
		0xc008,
		0x0016,
		0x000a,
		0x00ff,
	}

	/*cipherSuites := []uint16{
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0xC02B, // ECDHE-ECDSA-AES128-GCM-SHA256
		0xC02C, // ECDHE-ECDSA-AES256-GCM-SHA384
		0xC02F, // ECDHE-RSA-AES128-GCM-SHA256
		0xC030, // ECDHE-RSA-AES256-GCM-SHA384
	}*/
	cipherSuitesBytes := make([]byte, 2*len(cipherSuites))
	for i, cs := range cipherSuites {
		binary.BigEndian.PutUint16(cipherSuitesBytes[i*2:], cs)
	}

	compressionMethods := []byte{0x00} // null

	// Extensions: (curl)
	// a) Supported Versions
	supportedVersionsExt := buildSupportedVersionsExtension()
	// b) Key Share
	keyShareExt, err := buildKeyShareExtension(cfg.PQKeyShare)
	if err != nil {
		return nil, err
	}
	// c) SNI
	sniExtension := buildServerNameExtension(sni)
	// d) EC Point Formats
	ecPointsExt := buildEcPointFormatsExtension()
	// e) Supported Groups
	supportedGroupsExt := buildSupportedGroupsExtension(cfg.PQKeyShare)
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

func buildKeyShareEntry(group uint16, key []byte) ([]byte, error) {
	groupLen := len(key)
	entryLen := 2 + 2 + groupLen // group(2) + key_exchange_length(2) + key_exchange_data
	entry := make([]byte, entryLen)

	// group
	binary.BigEndian.PutUint16(entry[0:2], group)
	// key_exchange_length
	binary.BigEndian.PutUint16(entry[2:4], uint16(groupLen))
	// key_exchange_data
	copy(entry[4:], key)

	return entry, nil
}

func buildKeyShareExtension(PQKeyShare bool) ([]byte, error) {
	const x25519Group = uint16(0x001d)
	const x25519Len = 32
	x25519Key, err := hex.DecodeString(keyshareHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key for X25519 key_share: %w", err)
	}
	if len(x25519Key) != x25519Len {
		return nil, fmt.Errorf("keyShareHex must be exactly %d bytes for X25519", x25519Len)
	}

	x25519Entry, err := buildKeyShareEntry(x25519Group, x25519Key)
	if err != nil {
		return nil, fmt.Errorf("failed building X25519 KeyShareEntry: %w", err)
	}

	var pqEntry []byte
	if PQKeyShare {
		const pqGroup = uint16(0x11ec)
		pqKey, err := hex.DecodeString(pqkeyshareHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode pqkeyshareHex: %w", err)
		}
		pqEntry, err = buildKeyShareEntry(pqGroup, pqKey)
		if err != nil {
			return nil, fmt.Errorf("failed building PQ KeyShareEntry: %w", err)
		}
	}

	combinedEntries := append(x25519Entry, pqEntry...)

	ksListLen := make([]byte, 2)
	binary.BigEndian.PutUint16(ksListLen, uint16(len(combinedEntries)))
	data := append(ksListLen, combinedEntries...)

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

func buildSupportedGroupsExtension(PQKeyShare bool) []byte {
	// Example set: (curl)
	groups := []uint16{
		0x001d,
		0x0017,
		0x0018,
		0x0019,
	}

	if PQKeyShare {
		groups = append(groups, 0x11ec)
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
		return nil, fmt.Errorf("invalid hex reason string '%s': %w", reason, err)
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
			return nil, fmt.Errorf("failed building alert: %w", err)
		}
		return alert, nil

	default:
		return nil, fmt.Errorf("unknown PayloadType: %s", rec.PayloadType)
	}
}

type ServerHello struct {
	Length            uint16 `json:"Length"`
	Random            []byte `json:"Random"`
	SessionIDLength   uint8  `json:"SessionIDLength"`
	SessionID         []byte `json:"SessionID"`
	CipherSuite       string `json:"CipherSuite"`
	CompressionMethod uint8  `json:"CompressionMethod"`
	ExtensionsLength  uint16 `json:"ExtensionsLength"`
	CertificateLength uint16 `json:"CertificateLength"`
}

const (
	TLS12Version          = 0x0303
	TLS13Version          = 0x0304
	KeyShareExtension     = 0x0033
	KeyExchangeCurve25519 = 0x001d
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
	TLS_AES_256_GCM_SHA384                        = []byte{0x13, 0x02}
	TLS_AES_128_GCM_SHA256                        = []byte{0x13, 0x01}
)

func findKeyShare(data []byte) (keyExchangeGroup uint16, publicKey []byte, err error) {
	currentPos := 0
	for currentPos < len(data) {
		// Need at least 4 bytes to read extension type and length
		if currentPos+4 > len(data) {
			return 0, nil, fmt.Errorf("incomplete extension header")
		}

		// Read extension type (2 bytes)
		extType := binary.BigEndian.Uint16(data[currentPos : currentPos+2])
		// Read extension length (2 bytes)
		extLen := binary.BigEndian.Uint16(data[currentPos+2 : currentPos+4])

		// Move past header
		currentPos += 4

		// Check if this is key share extension (0x0033)
		if extType == 0x0033 {
			// Need 4 more bytes for key exchange group and key length
			if currentPos+4 > len(data) {
				return 0, nil, fmt.Errorf("incomplete key share data")
			}

			// Get key exchange group
			keyExchangeGroup = binary.BigEndian.Uint16(data[currentPos : currentPos+2])
			// Skip to key length
			currentPos += 2

			// Get key length
			keyLen := binary.BigEndian.Uint16(data[currentPos : currentPos+2])
			currentPos += 2

			// Extract the public key
			if currentPos+int(keyLen) > len(data) {
				return 0, nil, fmt.Errorf("incomplete public key data")
			}

			return keyExchangeGroup, data[currentPos : currentPos+int(keyLen)], nil
		}

		// Move to next extension
		currentPos += int(extLen)
	}

	return 0, nil, fmt.Errorf("key share extension not found")
}

func ParseServerHello(packets []gopacket.Packet) *ServerHello {
	var serverHello ServerHello
	for _, packet := range packets {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			data := tcpLayer.(*layers.TCP).Payload
			// log.Println("WTF: ", len(data))
			// log.Println("First 5 bytes: ", data[:6])
			// if len(data) > 5 && data[5] == 2 && data[0] == 22 {
			// 	log.Println("Check: len of payload: ", len(data))
			// }
			if len(data) > 81 && data[5] == 2 && data[0] == 22 {
				// data = data[3:]
				serverHello.Length = binary.BigEndian.Uint16(data[3:5])
				// Random starts at index 11 (3 + 8)
				serverHello.Random = data[11:43]
				// SessionID starts at index 43
				serverHello.SessionIDLength = data[43]
				serverHello.SessionID = data[44:76]
				// Cipher suite starts at index 76
				switch {
				case bytes.Equal(data[76:78], TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256):
					serverHello.CipherSuite = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
				case bytes.Equal(data[76:78], TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256):
					serverHello.CipherSuite = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
				case bytes.Equal(data[76:78], TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256):
					serverHello.CipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
				case bytes.Equal(data[76:78], TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384):
					serverHello.CipherSuite = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
				case bytes.Equal(data[76:78], TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256):
					serverHello.CipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
				case bytes.Equal(data[76:78], TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384):
					serverHello.CipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
				case bytes.Equal(data[76:78], TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA):
					serverHello.CipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
				case bytes.Equal(data[76:78], TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA):
					serverHello.CipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
				case bytes.Equal(data[76:78], TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA):
					serverHello.CipherSuite = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
				case bytes.Equal(data[76:78], TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA):
					serverHello.CipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
				case bytes.Equal(data[76:78], TLS_RSA_WITH_AES_128_GCM_SHA256):
					serverHello.CipherSuite = "TLS_RSA_WITH_AES_128_GCM_SHA256"
				case bytes.Equal(data[76:78], TLS_RSA_WITH_AES_256_GCM_SHA384):
					serverHello.CipherSuite = "TLS_RSA_WITH_AES_256_GCM_SHA384"
				case bytes.Equal(data[76:78], TLS_RSA_WITH_AES_128_CBC_SHA):
					serverHello.CipherSuite = "TLS_RSA_WITH_AES_128_CBC_SHA"
				case bytes.Equal(data[76:78], TLS_RSA_WITH_AES_256_CBC_SHA):
					serverHello.CipherSuite = "TLS_RSA_WITH_AES_256_CBC_SHA"
				case bytes.Equal(data[76:78], TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA):
					serverHello.CipherSuite = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
				case bytes.Equal(data[76:78], TLS_RSA_WITH_3DES_EDE_CBC_SHA):
					serverHello.CipherSuite = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
				case bytes.Equal(data[76:78], TLS_AES_256_GCM_SHA384):
					serverHello.CipherSuite = "TLS_AES_256_GCM_SHA384"
				case bytes.Equal(data[76:78], TLS_AES_128_GCM_SHA256):
					serverHello.CipherSuite = "TLS_AES_128_GCM_SHA256"
				default:
					fmt.Printf("Unknown cipher suite: %x\n", data[76:78])
				}
				// Compression method and extensions length start at index 78
				serverHello.CompressionMethod = data[78]
				serverHello.ExtensionsLength = binary.BigEndian.Uint16(data[79:81])

				// For now, if the server certificates tls record header does not fit into a single tcp packet we wont be able to find it
				// We would need to refragement the tls message
				data = data[int(serverHello.Length)+5:]
				var foundEncryptedExtensions bool
				i := 0
				for i < len(data) {
					if data[i] == 20 {
						i += 6
						continue
					}
					if data[i] == 23 && !foundEncryptedExtensions {
						foundEncryptedExtensions = true
						if i+5 < len(data) {
							skip := binary.BigEndian.Uint16(data[i+3 : i+5])
							i += int(skip) + 5
							continue
						}
					}
					if data[i] == 23 && foundEncryptedExtensions {
						if i+5 < len(data) {
							serverHello.CertificateLength = binary.BigEndian.Uint16(data[i+3 : i+5])
							break
						}
					}
				}
				return &serverHello
			}

		}
	}
	return nil
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	// TLS 1.3 specific label prefix
	labelPrefix := "tls13 "

	// Construct HKDF label
	hkdfLabel := make([]byte, 0, 4+len(labelPrefix)+len(label)+len(context))
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len(labelPrefix)+len(label)))
	hkdfLabel = append(hkdfLabel, labelPrefix...)
	hkdfLabel = append(hkdfLabel, label...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	// Create HKDF reader
	h := sha256.New
	hkdf := hkdf.Expand(h, secret, hkdfLabel)

	// Read derived key material
	output := make([]byte, length)
	if _, err := io.ReadFull(hkdf, output); err != nil {
		panic(err)
	}

	return output
}

func DecryptTLSMessage(serverPublicKey []byte, clientHelloBytes []byte, serverHelloBytes []byte, encryptedCert []byte) {
	x25519Key, err := hex.DecodeString(keyshareHex)
	if err != nil {
		log.Println("hex.DecodeString(keyshareHex) failed: ", err)
	}
	sharedSecret, err := curve25519.X25519(x25519Key, serverPublicKey)
	if err != nil {
		log.Println("Decrypting failed: ", err)
	}

	zeroKey := make([]byte, 32) // 32 zero bytes
	zeros := make([]byte, 32)   // another 32 zero bytes
	h := sha256.New
	earlySecret := hkdf.Extract(h, zeroKey, zeros)
	derivedSecret := hkdfExpandLabel(earlySecret, "derived", []byte{}, sha256.Size)
	handshakeSecret := hkdf.Extract(h, sharedSecret, derivedSecret)
	transcriptHash := sha256.Sum256(append(clientHelloBytes, serverHelloBytes...))
	serverHandshakeTrafficSecret := hkdfExpandLabel(handshakeSecret, "s hs traffic", transcriptHash[:], sha256.Size)
	key := hkdfExpandLabel(serverHandshakeTrafficSecret, "key", []byte{}, 16)
	iv := hkdfExpandLabel(serverHandshakeTrafficSecret, "iv", []byte{}, 12)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		log.Println("failed to create GCM: ", err)
	}

	// For each encrypted record:
	nonce := make([]byte, 12)
	copy(nonce, iv)
	// Use sequence number (0 for first record) in last 8 bytes
	binary.BigEndian.PutUint64(nonce[4:], uint64(0))

	// Record header (5 bytes) is additional data
	additionalData := encryptedCert[:5]
	// Encrypted portion starts after header
	ciphertext := encryptedCert[5:]

	_, err = aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		log.Println("aead.Open failed: %w", err)
	}

}
