package vaultstorage

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
	"github.com/davecgh/go-spew/spew"
	"go.uber.org/zap"
)

// DecryptOTP Decrypt OTP using stored private AES for specified public identifier
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
		log.Error("private ID mismatch", zap.String("opt_private_id", hex.EncodeToString(otp.PrivateID[:])), zap.String("key_private_id", key.PrivateID))
		return nil, common.ErrStorageDecryptFail
	}

	return otp, err
}

func (s *Service) StoreKey(k *key) error {
	path := fmt.Sprintf("secret/data/puppet/service/yubiserv/%s", k.PublicID)

	data := make(map[string]interface{})

	data["aes_key"] = k.AESKey
	if k.PrivateID != "" {
		data["private_id"] = k.PrivateID
	}

	secret, err := s.vault.Logical().Write(path, data)
	if err != nil {
		return err
	}

	spew.Dump(secret)
	return nil
}

func (s *Service) GetKey(publicId string) (*key, error) {

	path := fmt.Sprintf("secret/data/puppet/service/yubiserv/%s", publicId)

	secret, err := s.vault.Logical().Read(path)
	if err != nil {
		return nil, err
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

	var privateId string
	if privateId, ok = data["private_id"].(string); !ok {
		privateId = ""
	}

	s.log.Debug("secret loaded", zap.String("aes_key", aesKey))
	return &key{
		ID:        0,
		PublicID:  publicId,
		Created:   "",
		PrivateID: privateId,
		AESKey:    aesKey,
		LockCode:  "",
		Active:    true,
	}, nil

}

//
//func (s *Service) UpdateCounters(publicId string, usageCounter uint16, sessionCounter uint8) error {
//	log := s.log.With(
//		zap.String("public_id", publicId),
//	)
//	path := fmt.Sprintf("secret/data/puppet/service/yubiserv/%s", publicId)
//
//	secret, err := s.vault.Logical().JSONMergePatch(path, map[string]interface{}{
//		"usage_counter":   usageCounter,
//		"session_counter": sessionCounter,
//	})
//
//	spew.Dump(secret)
//
//	if err != nil {
//		log.Warn("cannot update counters in vault")
//		return err
//	}
//
//	return nil
//}
