package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kaitus/bookstore_users-api-golang/utils/errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic    = "X-Public"
	headerXClienID   = "X-Client-Id"
	headerXCallerID  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(request.Header.Get(headerXClienID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

func AutenticateRequest(request *http.Request) *errors.RestError {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClienID, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClienID)
	request.Header.Del(headerXCallerID)

}

func getAccessToken(accessTokenID string) (*accessToken, *errors.RestError) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenID))

	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("invalid restclient response when trying to get access token")
	}

	if response.StatusCode > 299 {
		var restErr errors.RestError
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to get access token")
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshal access token response")
	}
	return &at, nil
}
