package api

const (
	// ResponseCodeOK sent when OTP is successfully pass all checks.
	ResponseCodeOK = "OK"

	// ResponseCodeBadOTP sent when OTP does not pass validity checks.
	ResponseCodeBadOTP = "BAD_OTP"

	// ResponseCodeReplayedOTP sent when OTP in request is already seen before.
	ResponseCodeReplayedOTP = "REPLAYED_OTP"

	// ResponseCodeDelayedOTP is sent when the OTP timestamp is delayed.
	ResponseCodeDelayedOTP = "DELAYED_OTP"

	// ResponseCodeBadSignature is sent when HMAC signature is invalid.
	ResponseCodeBadSignature = "BAD_SIGNATURE"

	// ResponseCodeMissingParameter is sent when a request missing some mandatory params.
	ResponseCodeMissingParameter = "MISSING_PARAMETER"

	// ResponseCodeNoSuchClient is sent when a client is not found.
	ResponseCodeNoSuchClient = "NO_SUCH_CLIENT"

	// ResponseCodeOperationNotAllowed is sent when a check operation is not allowed.
	ResponseCodeOperationNotAllowed = "OPERATION_NOT_ALLOWED"

	// ResponseCodeBackendError is sent when the backend has errors.
	ResponseCodeBackendError = "BACKEND_ERROR"

	// ResponseCodeNotEnoughAnswers is sent where there is no quorum on check servers.
	ResponseCodeNotEnoughAnswers = "NOT_ENOUGH_ANSWERS"

	// ResponseCodeReplayedRequest is sent when the request is replayed.
	ResponseCodeReplayedRequest = "REPLAYED_REQUEST"
)

var (
	_ = ResponseCodeNotEnoughAnswers
	_ = ResponseCodeReplayedRequest
	_ = ResponseCodeOperationNotAllowed
	_ = ResponseCodeDelayedOTP
	_ = ResponseCodeBackendError
)
