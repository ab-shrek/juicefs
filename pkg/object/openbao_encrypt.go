/*
 * JuiceFS, Copyright 2020 Juicedata, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package object

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	openbao "github.com/openbao/openbao/api/v2"
	"github.com/pquerna/otp/totp"
)

type openBaoEncryptor struct {
	openBaoURL string
	totpSecret string
}

// NewOpenBaoEncryptor initializes a new OpenBao-based encryptor
func NewOpenBaoEncryptor(openBaoURL, totpSecret string) Encryptor {
	return &openBaoEncryptor{openBaoURL, totpSecret}
}

// generateTOTP generates a time-based one-time password
func (e *openBaoEncryptor) generateTOTP() (string, error) {
	return totp.GenerateCode(e.totpSecret, time.Now())
}

func enableTransitEngine(client *openbao.Client) error {
	// Enable the transit secrets engine
	options := map[string]interface{}{
		"type": "transit",
	}

	// options := &openbao.MountInput{
	// 	// Fill in the fields according to your needs
	// 	Type: "transit", // For example, specify the type of mount
	// 	// Add other fields if required, such as Description, Options, etc.
	// }
	// The path here is just "transit" - this is the mount point
	// return client.Sys().Mount("transit", options)

	// Check vault status first
	sealStatus, err := client.Sys().SealStatus()
	if err != nil {
		return fmt.Errorf("failed to check seal status: %v", err)
	}
	logger.Errorf("Vault seal status - Sealed: %v, NumShares: %d, Threshold: %d",
		sealStatus.Sealed, sealStatus.N, sealStatus.T)

	// Check current token info
	tokenInfo, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("failed to lookup token info: %v", err)
	}
	logger.Errorf("Token policies: %v", tokenInfo.Data["policies"])

	// Try to mount and capture detailed error
	_, err = client.Logical().Write("sys/mounts/transit", options)
	if err != nil {
		// Try to get more error details
		if responseErr, ok := err.(*openbao.ResponseError); ok {
			return fmt.Errorf("failed to enable transit engine: status=%d, errors=%v",
				responseErr.StatusCode, responseErr.Errors)
		}
		return fmt.Errorf("failed to enable transit engine with unknown error: %v", err)
	}
	return nil
}

// checkOpenBaoServer ensures the OpenBao server is running
func (e *openBaoEncryptor) checkOpenBaoServer() error {
	const healthCheckEndpoint = "/v1/sys/health"
	url := e.openBaoURL + healthCheckEndpoint

	// Send a GET request to the health check endpoint
	resp, err := http.Get(url)
	if err == nil && resp.StatusCode == http.StatusOK {
		return nil // Server is running
	}

	// Server not running, start it
	// cmd := exec.Command("openbao", "server", "-dev", "-dev-root-token-id=dev-only-token")
	cmd := exec.Command("openbao", "server", "-config=/Users/mario/Desktop/dont_enter/opensource/config.hcl")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	logger.Errorf("Starting OpenBao server...")

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start OpenBao server: %v", err)
	}

	logger.Errorf("OpenBao server started successfully. Waiting for it to become ready...")
	// Wait for the server to be ready
	time.Sleep(2 * time.Second)
	return nil
}

// Encrypt sends plaintext to OpenBao for encryption
func (e *openBaoEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	// totpCode, err := e.generateTOTP()
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to generate TOTP: %w", err)
	// }
	// Ensure the server is running
	if err := e.checkOpenBaoServer(); err != nil {
		return nil, err
	}

	config := openbao.DefaultConfig()
	// logger.Errorf("mario config %v", config)
	config.Address = "http://127.0.0.1:8200"
	client, err := openbao.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize OpenBao client: %v", err)
	}
	client.SetToken("dev-only-token")

	var unsealKeys []string
	var rootToken string

	// Check if initialized
	initStatus, err := client.Sys().InitStatus()
	if !initStatus {
		// Perform initialization if needed
		initRequest := &openbao.InitRequest{
			SecretShares:    5,
			SecretThreshold: 3,
		}
		initResponse, err := client.Sys().Init(initRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize: %v", err)
		}
		// Handle initialization response, store unseal keys and root token
		unsealKeys = initResponse.Keys
		rootToken = initResponse.RootToken

		// Optionally log or securely store these
		client.SetToken(rootToken)
	}

	// Unseal if necessary
	for _, key := range unsealKeys {
		_, err := client.Sys().Unseal(key)
		// Handle unseal process
		if err != nil {
			return nil, fmt.Errorf("unsealing failed: %v", err)
		}
	}

	logger.Errorf("going to enable transit engine...")
	// 1. First, enable the transit engine if not already enabled
	err = enableTransitEngine(client)
	if err != nil {
		fmt.Printf("Transit engine might already be enabled: %v", err)
	}
	logger.Errorf("transit engine enabled...")

	// 2. Create a new encryption key if it doesn't exist
	err = createEncryptionKey(client)

	if err != nil {
		fmt.Printf("Encryption key might already exist: %v", err)
	}

	// 3. Now we can use the transit engine for encryption
	encodedText := base64.StdEncoding.EncodeToString([]byte(plaintext))
	ciphertext, err := encryptText(client, encodedText)
	if err != nil {
		return nil, fmt.Errorf("Encryption failed: %v", err)
	}
	logger.Infof("mario encoded text %v", ciphertext)
	return []byte(ciphertext), nil
}

func encryptText(client *openbao.Client, plaintext string) (string, error) {
	// Encode the plaintext in base64
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))

	// Prepare the encryption request
	data := map[string]interface{}{
		"plaintext": encoded,
	}

	// The full path for encryption:
	// transit/encrypt/<key-name>
	secret, err := client.Logical().Write("transit/encrypt/my-encryption-key", data)
	if err != nil {
		return "", err
	}

	return secret.Data["ciphertext"].(string), nil
}

func decryptText(client *openbao.Client, ciphertext string) (string, error) {
	// Prepare the decryption request
	data := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	// The full path for decryption:
	// transit/decrypt/<key-name>
	secret, err := client.Logical().Write("transit/decrypt/my-encryption-key", data)
	if err != nil {
		return "", err
	}

	// Decode the base64 encoded result
	decoded, err := base64.StdEncoding.DecodeString(secret.Data["plaintext"].(string))
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

func createEncryptionKey(client *openbao.Client) error {
	// Create a new encryption key
	options := map[string]interface{}{
		"type":                  "aes256-gcm96", // Default encryption algorithm
		"convergent_encryption": true,
		"derived":               true,
	}

	// The path includes transit/keys/ and then the key name
	_, err := client.Logical().Write("transit/keys/my-encryption-key", options)
	return err
}

// Decrypt sends ciphertext to OpenBao for decryption
func (e *openBaoEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	// totpCode, err := e.generateTOTP()
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to generate TOTP: %w", err)
	// }

	reqBody := map[string]interface{}{
		"totp_code": e.totpSecret,
		"data":      ciphertext,
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(fmt.Sprintf("%s/decrypt", e.openBaoURL), "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to send decrypt request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("decryption failed with status %d", resp.StatusCode)
	}

	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, fmt.Errorf("failed to parse decrypt response: %w", err)
	}

	decryptedData, ok := respData["decrypted_data"].(string)
	if !ok {
		return nil, errors.New("invalid response format")
	}

	return []byte(decryptedData), nil
}

var _ ObjectStorage = &encrypted{}
