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

	key, err := s.getKey(publicID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, common.ErrStorageNoKey
		}
		return nil, err
	}

	if !key.Active {
		return nil, common.ErrStorageKeyInactive
	}

	aesKey, err := hex.DecodeString(key.AESKey)
	if err != nil {
		return nil, err
	}

	binToken, err := hex.DecodeString(misc.Modhex2hex(token))
	if err != nil {
		return nil, err
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

	return otp, err
}

// StoreKey in vault storage.
func (s *Service) StoreKey(k *Key) error {
	path := fmt.Sprintf("%s/%s", s.vaultPath, k.PublicID)

	data := make(map[string]interface{})

	data["aes_key"] = k.AESKey
	if k.PrivateID != "" {
		data["private_id"] = k.PrivateID
	}

	_, err := s.vault.Logical().Write(path, data)
	if err != nil {
		return err
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
			return nil, err
		}
	}

	if secret == nil {
		s.log.Warn("public_id not found in vault storage", zap.String("path", path))
		return nil, errors.New("key not found")
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("data type assertion failed: %T %#v", secret.Data["data"], secret.Data["data"])
	}

	var aesKey string
	if aesKey, ok = data["aes_key"].(string); !ok {
		s.log.Warn("aes_key not found in vault storage", zap.String("path", path))
		return nil, errors.New("key secret not found")
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
