package messages

import (
	"net/http"
)

type body map[string]interface{}

type Response struct {
	body       body
	httpStatus int
}

var ResponseMap = make(map[string]Response)

func readFromMap(key string) (int, body) {
	resp, available := ResponseMap[key]
	if available {
		return resp.httpStatus, resp.body
	}
	return http.StatusInternalServerError, generalResponse("something went wrong")
}

func generalResponse(message string) body {
	return body{
		"message": message,
	}
}
func validationResponse(message string, err error) (int, body) {
	return http.StatusBadRequest, body{
		"message":          message,
		"validation_error": err,
	}
}

func AddToMap(message string, httpStatus int) {
	_, available := ResponseMap[message]
	if available {
		return
	}
	ResponseMap[message] = Response{
		body:       generalResponse(message),
		httpStatus: httpStatus,
	}
}
