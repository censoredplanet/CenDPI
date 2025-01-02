package http

import (
	"strings"
)

// 1400 bytes of padding
const padding = "8d99a4b0f28d35fc3d18a5a655f2948969acd4210ded118bd7e7797ee3bfd9170d80723237666ef70336804c361ea5a333c04d93b94a770b8e41374bd305cbd538b0076cb56c721c0fd4779c42bcb26828c0e095ae9272f4bcac76b69e83d11cf12321bca801e39710c8630f38918e7f499570724b5b76087b4197a98c1819e5bf24407ca4139a05e62bb6cb36b0b7c2ae1617260416af32b95f578209f3b1ccc66ca5699751470d3f47ad663024b88827dad946416365bf09461fb40f5526785f5949bb99843403393d962783fa26beb74fc80b6033e2adeab941df2b08c0e94b70a7ac95c682774302d569a2b09c0b76b0a74b0c5b7676828d192a73d47c771519398840d2eb20d3608ca7c4ab47006ed3710e0c8c32106a6b99d684a9a43ad91835977352fe39b09d7261f305826409d0660c315a54abb34b1330bc2923e0425977af6bcca805b74d81a241d0ac222dfaa0127576d6b6365ac59cecd045d241403ab95e987cc655d3c125d360233859a0a86e809843a9385f4bfb0015e2619fc73c6636cc684575ed610c281717c8e89d72788194788bd1603bbd5151d3706ce8951a1db2568f5ac9c1e92f7447460585ba46785488e8961fac47b6c3bbea640e58221a28d323d4558b70b72b24cc138147af82640b2af118abb8c46bba010f989baa729ca30c93630c07d88c7771321049f1b637245bd1b3bd3580a412fb0dc605cedff37d7e8bb7f5821d82ab3c142a58d2232326784aa1281b21e8058d6a46778ba4893452830c00a7715578fa668c554a0883b0350cce3d03a63d268af5454421f43780b7596c6131f7e7a3e9e0cb29288bf809632c9437097b107d37b7512b9660f755e39071f9f4a9d1ba162d7c473eb6a310ba8b6d773773ef755e39071f9f4a9d1ba162d7c473eb6a310ba8b6d773773ef755e39071f9f4a9d1ba162d7c473eb6a310ba8b6d773773ease32d214d773773ef755e39071"

type HTTPConfig struct {
	Request            string
	Domain             string
	AllCapsHostDomain  bool
	AllLowerHostDomain bool
    Padding            bool
}

func BuildHTTPRequest(cfg *HTTPConfig) ([]byte, error) {
	hostDomain := cfg.Domain
	if cfg.AllCapsHostDomain {
		hostDomain = strings.ToUpper(hostDomain)
	} else if cfg.AllLowerHostDomain {
		hostDomain = strings.ToLower(hostDomain)
	}
	// replace ${} with cfg.Domain
	request := cfg.Request
	request = strings.Replace(request, "${}", hostDomain, 1)

    if cfg.Padding {
        request = strings.Replace(request, "\r\n\r\n", "\r\nX-Padding: "+padding+"\r\n\r\n", 1)
	}

	return []byte(request), nil
}
