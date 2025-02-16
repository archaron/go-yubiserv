// Package vaultstorage implements vault keys store.
package vaultstorage

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"

	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
)

// DecryptOTP Decrypt OTP using stored private AES for specified public identifier.
func (s *Service) DecryptOTP(publicID, token string) (*common.OTP, error) {
	log := s.log.With(
		zap.String("public_id", publicID),
		zap.String("token", token),
	)

	key, err := s.getKeyFunc(publicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, common.ErrStorageNoKey
		}

		return nil, err
	}

	if !key.Active {
		return nil, common.ErrStorageKeyInactive
	}

	aesKey, err := hex.DecodeString(key.AESKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key: %w", err)
	}

	binToken, err := hex.DecodeString(misc.ModHexToHex(token))
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	otp := &common.OTP{}
	err = otp.Decrypt(aesKey, binToken)

	if err != nil {
		log.Error("AES decryption failed")

		return nil, common.ErrStorageDecryptFail
	}

	if hex.EncodeToString(otp.PrivateID[:]) != key.PrivateID {
		log.Error("private ID mismatch",
			zap.String("opt_private_id", hex.EncodeToString(otp.PrivateID[:])),
			zap.String("key_private_id", key.PrivateID),
		)

		return nil, common.ErrStorageDecryptFail
	}

	return otp, nil
}

// StoreKey in vault storage.
func (s *Service) StoreKey(k *Key) error {
	path := fmt.Sprintf("%s/%s", s.vaultPath, k.PublicID)

	data := make(map[string]interface{})

	data["aes_key"] = k.AESKey
	if k.PrivateID != "" {
		data["private_id"] = k.PrivateID
	}

	if _, err := s.vault.Logical().Write(path, data); err != nil {
		return fmt.Errorf("vault store key: %w", err)
	}

	return nil
}

// GetKey gets Key from storage by public id.
func (s *Service) GetKey(publicID string) (*Key, error) {
	path := fmt.Sprintf("%s/%s", s.vaultPath, publicID)

	secret, err := s.vault.Logical().Read(path)
	if err != nil {
		var re *api.ResponseError
		if !errors.As(err, &re) {
			return nil, fmt.Errorf("vault get key: %w", err)
		}
	}

	if secret == nil {
		s.log.Warn("public_id not found in vault storage", zap.String("path", path))

		return nil, common.ErrStorageNoKey
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		s.log.Warn("data type assertion failure in vault storage", zap.String("path", path), zap.Any("data", secret.Data))

		return nil, common.ErrStorageDecryptFail
	}

	var aesKey string

	if aesKey, ok = data["aes_key"].(string); !ok {
		s.log.Warn("aes_key not found in vault storage", zap.String("path", path))

		return nil, common.ErrStorageNoKey
	}

	var privateID string
	if privateID, ok = data["private_id"].(string); !ok {
		privateID = ""
	}

	return &Key{
		ID:        0,
		PublicID:  publicID,
		Created:   "",
		PrivateID: privateID,
		AESKey:    aesKey,
		LockCode:  "",
		Active:    true,
	}, nil
}
