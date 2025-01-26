package common

const (
	// Restrictions
	TokenLength    = 32
	PublicIDLength = 12
	OTPMaxLength   = TokenLength + PublicIDLength
	NonceMinLength = 16
	NonceMaxLength = 40
)
