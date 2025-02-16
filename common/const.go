package common

const (
	// TokenLength is the length of OTP token part.
	TokenLength = 32

	// PublicIDLength is the length of public user id part.
	PublicIDLength = 12

	// LockPWSize field size in bytes.
	LockPWSize = 6

	// PrivateIDSize size in bytes.
	PrivateIDSize = 6

	// OTPMaxLength is the maximal OTP token length.
	OTPMaxLength = TokenLength + PublicIDLength

	// NonceMinLength represents minimal request nonce length.
	NonceMinLength = 16

	// NonceMaxLength represents maximal request nonce length.
	NonceMaxLength = 40
)
