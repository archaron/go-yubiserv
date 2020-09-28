package common

const (
	// Restrictions
	TokenLength       = 32
	PublicIDMaxLength = 16
	OTPMinLength      = TokenLength
	OTPMaxLength      = TokenLength + PublicIDMaxLength
	NonceMinLength    = 16
	NonceMaxLength    = 40
)
