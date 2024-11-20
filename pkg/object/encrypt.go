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
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
)

type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// encrypted wraps ObjectStorage with encryption
type encrypted struct {
	ObjectStorage
	enc Encryptor
}

// NewDataEncryptor creates an Encryptor based on the encryption algorithm

func NewDataEncryptor(encType, encryptAlgo string, privKey interface{}) (Encryptor, error) {
	switch encryptAlgo {
	case "openbao":
		// Assuming you have the URL and secret to pass
		openBaoURL := "https://openbao.example.com"
		totpSecret := "your_totp_secret" // Replace with actual TOTP secret
		return NewOpenBaoEncryptor(openBaoURL, totpSecret), nil
	case "rsa":
		// Assuming you load RSA key
		if privKey == nil {
			return nil, fmt.Errorf("RSA private key cannot be nil")
		}
		// Ensure the key passed is actually a valid RSA key
		privateKey, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid RSA private key type")
		}
		return NewRSADataEncryptor(NewRSAEncryptor(privateKey), encType)
	default:
		return nil, errors.New("unsupported encryption algorithm")
	}
}

// NewEncrypted returns encrypted object storage
func NewEncrypted(o ObjectStorage, enc Encryptor) ObjectStorage {
	return &encrypted{o, enc}
}

func (e *encrypted) String() string {
	return fmt.Sprintf("%s(encrypted)", e.ObjectStorage)
}

func (e *encrypted) Get(key string, off, limit int64, getters ...AttrGetter) (io.ReadCloser, error) {
	r, err := e.ObjectStorage.Get(key, 0, -1, getters...)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	plain, err := e.enc.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	l := int64(len(plain))
	if off > l {
		off = l
	}
	if limit == -1 || off+limit > l {
		limit = l - off
	}
	data := plain[off : off+limit]
	return io.NopCloser(bytes.NewBuffer(data)), nil
}

func (e *encrypted) Put(key string, in io.Reader, getters ...AttrGetter) error {
	plain, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	ciphertext, err := e.enc.Encrypt(plain)
	if err != nil {
		return err
	}
	return e.ObjectStorage.Put(key, bytes.NewReader(ciphertext), getters...)
}
