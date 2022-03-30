package clients

import (
	"auth/config"
	"auth/log"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"
)

type emailClient struct {
	Client *http.Client
}

var myEmailClient emailClient

func ConnectEmail() {
	timeout := config.Mail().Timeout * time.Second
	var netTransport = &http.Transport{
		DialContext:         (&net.Dialer{Timeout: timeout, KeepAlive: time.Minute}).DialContext,
		TLSHandshakeTimeout: timeout,
		MaxIdleConnsPerHost: 10,
	}
	myEmailClient = emailClient{
		Client: &http.Client{
			Timeout:   timeout,
			Transport: netTransport,
		},
	}
}

func Email() emailClient {
	return myEmailClient
}

func (ec emailClient) PrepareEmailURL(path string, body []byte, method string) http.Request {
	baseURL := config.Mail().ServiceURL
	reqURL, _ := url.Parse(fmt.Sprintf("%s/%s", baseURL, path))

	req := http.Request{
		Method: method,
		URL:    reqURL,
		Header: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body:          ioutil.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	return req
}

// Send This function will send the actual email request
func (ec emailClient) Send(path string, emailBody interface{}) error {
	byteData, _ := json.Marshal(emailBody)

	req := ec.PrepareEmailURL(path, byteData, "POST")

	res, err := ec.Client.Do(&req)
	if err != nil {
		log.Error(err, " on email send")
		return err
	}
	log.Info(fmt.Sprintf("email service status code after %v email send: %v ", path, res.StatusCode))

	return nil
}
