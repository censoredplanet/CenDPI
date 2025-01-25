package http

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// 1200 bytes of padding
// Perhaps we could just randomly generate the padding for each probe?
const padding = "8d99a4b0f28d35fc3d18a5a655f2948969acd4210ded118bd7e7797ee3bfd917" +
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
	"4a0883b0350cce3d03a63d268af5454421f43780b7596c6131f7e7a3e9e0cb29288bf80963"

type HTTPConfig struct {
	Request            string `yaml:"request"`
	Domain             string
	Padding            bool `yaml:"padding"`
	LongPadding		   bool `yaml:"longPadding"`
}

func (h *HTTPConfig) UnmarshalYAML(node *yaml.Node) error {
	type base HTTPConfig
	raw := struct {
		base `yaml:",inline"`
	}{}

	if err := node.Decode(&raw); err != nil {
		return err
	}

	*h = HTTPConfig(raw.base)

	return nil
}

func BuildHTTPRequest(cfg *HTTPConfig) ([]byte, error) {
	hostDomain := cfg.Domain
	
	// replace ${} with cfg.Domain
	request := cfg.Request
	request = strings.Replace(request, "${}", hostDomain, 1)

	if cfg.Padding {
		request = strings.Replace(request, "Host:", "X-Padding: "+padding+"\r\nHost:", 1)
	} else if cfg.LongPadding {
		request = strings.Replace(request, "Host:", "X-Padding: "+padding+padding+"\r\nHost:", 1)
	}

	return []byte(request), nil
}
