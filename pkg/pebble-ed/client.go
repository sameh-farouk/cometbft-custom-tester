package pebble_ed

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"

	"github.com/cometbft/cometbft-load-test/pkg/loadtest"
)

const (
	KVStoreClientIDLen int = 5 // Allows for 6,471,002 random client IDs (62C5)
	kvstoreMinValueLen int = 1 // We at least need 1 character in a key/value pair's value.
)

var kvstoreMaxTxsByKeySuffixLen = []uint64{
	0,              // 0
	62,             // 1
	1891,           // 2
	37820,          // 3
	557845,         // 4
	6471002,        // 5
	61474519,       // 6
	491796152,      // 7
	3381098545,     // 8
	20286591270,    // 9
	107518933731,   // 10
	508271323092,   // 11
	2160153123141,  // 12
	8308281242850,  // 13
	29078984349975, // 14
	93052749919920, // 15
}

// MyABCIAppClientFactory creates instances of MyABCIAppClient
type MyABCIAppClientFactory struct{}

// MyABCIAppClientFactory implements loadtest.ClientFactory
var _ loadtest.ClientFactory = (*MyABCIAppClientFactory)(nil)

// MyABCIAppClient is responsible for generating transactions. Only one client
// will be created per connection to the remote CometBFT RPC endpoint, and
// each client will be responsible for maintaining its own state in a
// thread-safe manner.
type MyABCIAppClient struct{
	batchSize int
	txCounter int
	senders   []string
}

// MyABCIAppClient implements loadtest.Client
var _ loadtest.Client = (*MyABCIAppClient)(nil)

func (f *MyABCIAppClientFactory) ValidateConfig(cfg loadtest.Config) error {
	maxTxsPerEndpoint := cfg.MaxTxsPerEndpoint()
	if maxTxsPerEndpoint < 1 {
		return fmt.Errorf("cannot calculate an appropriate maximum number of transactions per endpoint (got %d)", maxTxsPerEndpoint)
	}
	return nil
}

func (f *MyABCIAppClientFactory) NewClient(cfg loadtest.Config) (loadtest.Client, error) {
	batchSize := cfg.Size
	senderIds := []string{"1", "2", "3", "4"}
	return &MyABCIAppClient{
		batchSize: batchSize,
		txCounter: 0,
		senders:   senderIds,
	}, nil
}

var privateKeyMap = map[string]string{
    "1": "23e980b97c67af9b94319b6672049fbd2f9992eaf6a567a2b5a66286e527e8e9c8af5ee74756bb934c9c3f93a3ffa4125c93d8a76619a1834f4511334d83d45f" ,
    "2": "11a2070b5bf25002c43d238117840fb97492266d3e0fb7637b069d5569b5d8283382d764d3e30ce4c3aab066335a558e8f632d2aaf161e6aa5615c57176cfbca",
    "3": "376384a0c4d4ef4e95bf980acea6ec6d7b8bbdaa06d91ca68383d018e885dda204c01c7d4f6c784504fce83f97968145e8aa6ca461ec19f3a685466152f17644" ,
    "4": "7403b7706deba2d8d036d00c5e1e087542fff733b1b3f1b776bf2fa64bcd5d98d06a22ce4b7a59ceac3a898504901f41e27491ed3cc90e8ee46ac43e9305d61a",
}

type Transfer struct {
    Id        string `json:"id"`
    Sender    string `json:"sender"`
    Dest      string `json:"dest"`
    Amount    string `json:"amount"`
    Signature string `json:"signature"`
}


func (t *Transfer) Challenge() []byte {
    challenge := []byte{}
    challenge = append(challenge, []byte(t.Id)...)
    challenge = append(challenge, []byte(t.Sender)...)
    challenge = append(challenge, []byte(t.Dest)...)
    challenge = append(challenge, []byte(t.Amount)...)
    return challenge
}

// GenerateTx must return the raw bytes that make up the transaction for your
// ABCI app. The conversion to base64 will automatically be handled by the
// loadtest package, so don't worry about that. Only return an error here if you
// want to completely fail the entire load test operation.
func (c *MyABCIAppClient) GenerateTx() ([]byte, error) {
	n := c.batchSize
	txData := ""
	for range n {
		c.txCounter++
		senderIdx := rand.Intn(len(c.senders))
		sender := c.senders[senderIdx]
		
		var dest string
		for {
			destIdx := rand.Intn(len(c.senders))
			dest = c.senders[destIdx]
			if dest != sender {
				break
			}
		}
		
		amount := rand.Intn(500) + 1
		
		transfer := Transfer{
			Id:     strconv.Itoa(c.txCounter),
			Sender: sender,
			Dest:   dest,
			Amount: strconv.Itoa(amount),
		}
		
		challenge := transfer.Challenge()
		
		privKeyHex := privateKeyMap[sender]
		privKeyBytes, err := hex.DecodeString(privKeyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key: %v", err)
		}
		
		privateKey := ed25519.PrivateKey(privKeyBytes)
		signature := ed25519.Sign(privateKey, challenge)
		
		transfer.Signature = hex.EncodeToString(signature)
		txData += fmt.Sprintf("%s=%s=%s=%s=%s", 
			transfer.Id,
			transfer.Sender, 
			transfer.Dest, 
			transfer.Amount, 
			transfer.Signature)
			txData += ":"
	}
	txData = txData[:len(txData)-1] 
    return []byte(txData), nil
}
