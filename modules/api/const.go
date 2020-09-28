package api

const (
	ResponseCodeOK                  = "OK"
	ResponseCodeBadOTP              = "BAD_OTP"
	ResponseCodeReplayedOTP         = "REPLAYED_OTP"
	ResponseCodeDelayedOTP          = "DELAYED_OTP"
	ResponseCodeBadSignature        = "BAD_SIGNATURE"
	ResponseCodeMissingParameter    = "MISSING_PARAMETER"
	ResponseCodeNoSuchClient        = "NO_SUCH_CLIENT"
	ResponseCodeOperationNotAllowed = "OPERATION_NOT_ALLOWED"
	ResponseCodeBackendError        = "BACKEND_ERROR"
	ResponseCodeNotEnoughAnswers    = "NOT_ENOUGH_ANSWERS"
	ResponseCodeReplayedRequest     = "REPLAYED_REQUEST"
)
