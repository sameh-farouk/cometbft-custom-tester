package pebble_ed

import (
	"crypto/ed25519"
	"encoding/binary"
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
	keyPrefix    []byte // Contains the client ID
	keySuffixLen int
	valueLen     int
	priKey		ed25519.PrivateKey
	pubKey		ed25519.PublicKey
	txCounter uint64
	senders   []string
}

// MyABCIAppClient implements loadtest.Client
var _ loadtest.Client = (*MyABCIAppClient)(nil)

func (f *MyABCIAppClientFactory) ValidateConfig(cfg loadtest.Config) error {
	maxTxsPerEndpoint := cfg.MaxTxsPerEndpoint()
	if maxTxsPerEndpoint < 1 {
		return fmt.Errorf("cannot calculate an appropriate maximum number of transactions per endpoint (got %d)", maxTxsPerEndpoint)
	}
	minKeySuffixLen, err := requiredKVStoreSuffixLen(maxTxsPerEndpoint)
	if err != nil {
		return err
	}
	// "[client_id][random_suffix]=[value]"
	minTxSize := KVStoreClientIDLen + minKeySuffixLen + 1 + kvstoreMinValueLen
	if cfg.Size < minTxSize {
		return fmt.Errorf("transaction size %d is too small for given parameters (should be at least %d bytes)", cfg.Size, minTxSize)
	}
	return nil
}

func (f *MyABCIAppClientFactory) NewClient(cfg loadtest.Config) (loadtest.Client, error) {
	keyPrefix := []byte(randStr(KVStoreClientIDLen))
	keySuffixLen, err := requiredKVStoreSuffixLen(cfg.MaxTxsPerEndpoint())
	if err != nil {
		return nil, err
	}
	keyLen := len(keyPrefix) + keySuffixLen
	// value length = key length - (32 bytes + 64 bytes)(public key + signature) (to cater for "=" symbol)
	valueLen := cfg.Size - keyLen - (32+64)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	senderIds := []string{"1", "2", "3", "4"}
	return &MyABCIAppClient{
		keyPrefix:    keyPrefix,
		keySuffixLen: keySuffixLen,
		valueLen:     valueLen,
		priKey: 	priv,
		pubKey:		pub,
		txCounter: 0,
		senders:   senderIds,
	}, nil
}

func requiredKVStoreSuffixLen(maxTxCount uint64) (int, error) {
	for l, maxTxs := range kvstoreMaxTxsByKeySuffixLen {
		if maxTxCount < maxTxs {
			if l+1 > len(kvstoreMaxTxsByKeySuffixLen) {
				return -1, fmt.Errorf("cannot cater for maximum tx count of %d (too many unique transactions, suffix length %d)", maxTxCount, l+1)
			}
			// we use l+1 to minimize collision probability
			return l + 1, nil
		}
	}
	return -1, fmt.Errorf("cannot cater for maximum tx count of %d (too many unique transactions)", maxTxCount)
}

var privateKeyMap = map[string]string{
    "1": "1111111111111111111111111111111111111111111111111111111111111111" ,
    "2": "2222222222222222222222222222222222222222222222222222222222222222",
    "3": "3333333333333333333333333333333333333333333333333333333333333333" ,
    "4": "4444444444444444444444444444444444444444444444444444444444444444",
}

type Transfer struct {
    Id        uint64 `json:"id"`
    Sender    string `json:"sender"`
    Dest      string `json:"dest"`
    Amount    string `json:"amount"`
    Signature string `json:"signature"`
}

// Transaction struct matching the application's expected format
type Transaction struct {
    Transfers []Transfer `json:"transfers"`
}

func (t *Transfer) Challenge() []byte {
    challenge := []byte{}
    numBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(numBytes, t.Id)
    challenge = append(challenge, numBytes...)
    challenge = append(challenge, []byte("=")...)
    challenge = append(challenge, []byte(t.Sender)...)
    challenge = append(challenge, []byte("=")...)
    challenge = append(challenge, []byte(t.Dest)...)
    challenge = append(challenge, []byte("=")...)
    challenge = append(challenge, []byte(t.Amount)...)
    return challenge
}

// GenerateTx must return the raw bytes that make up the transaction for your
// ABCI app. The conversion to base64 will automatically be handled by the
// loadtest package, so don't worry about that. Only return an error here if you
// want to completely fail the entire load test operation.
func (c *MyABCIAppClient) GenerateTx() ([]byte, error) {
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
        Id:     c.txCounter,
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
    
    txData := fmt.Sprintf("%s=%s=%s=%s=%s", 
        formatUint64(transfer.Id),
        transfer.Sender, 
        transfer.Dest, 
        transfer.Amount, 
        transfer.Signature)
    
    return []byte(txData), nil
}

func formatUint64(n uint64) string {
    bytes := make([]byte, 8)
    binary.BigEndian.PutUint64(bytes, n)
    return string(bytes)
}