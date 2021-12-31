package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/google/logger"

	retry "github.com/avast/retry-go"
)

// WrappedToken is Token with a better expiration field
type WrappedToken struct {
	Token
	ExpiresAt time.Time
}

// Token represents Azure OAuth token returned by successful authentication
// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#successful-response-3
type Token struct {
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	ExtExpiresIn int    `json:"ext_expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// graphClient http requests will automatically include auth token in header so caller does not have to add it
type graphClient struct {
	c http.Client
	t WrappedToken
	v string
}

// Wrapped returns a *WrappedToken from a normal Token
func (t *Token) Wrapped() *WrappedToken {
	var wt *WrappedToken = &WrappedToken{}
	wt.Token = *t
	wt.ExpiresAt = time.Now().Add(time.Second * time.Duration(t.ExpiresIn))
	return wt
}

// NewGraphClient returns a *graphClient with a default http client and token set
func NewGraphClient(w *WrappedToken) (*graphClient, error) {
	return &graphClient{
		c: *http.DefaultClient,
		t: *w,
		v: "beta",
	}, nil
}

// Get crafts a http GET request and calls graphClient.Do() to execute
func (c *graphClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Get crafts a http POST request and calls graphClient.Do() to execute
func (c *graphClient) Post(url string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	return c.Do(req)
}

// GetBlob retrieves a blob from Azure Blob container by providing required headers
// and finally calling graphClient.Do()
func (c *graphClient) GetBlob(container, blob string) (*http.Response, error) {
	uri := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", storageAccount, container, blob)
	logger.Infof("requesting %s", uri)
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("x-ms-version", "2019-12-12")
	uts := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Add("Date", uts)
	return c.Do(req)
}

// Do adds the access token to Authorization header before calling graphClient.c.Do()
// graphClient.c.Do() uses the http.Client that is inside graphClient
func (c *graphClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.t.AccessToken))
	return c.c.Do(req)
}

// AuthErr captures errors we might get while
// attempting to get DeviceCodeResponse
type AuthErr struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code#device-authorization-response
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

type DeviceCodePollingError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
	Timestamp        string `json:"time_stamp"`
	TraceID          string `json:"trace_id"`
	CorrelationID    string `json:"correlation_id"`
	ErrorURI         string `json:"error_uri"`
}

var (
	ErrAuthPending         = errors.New("authorization_pending")
	ErrAuthDeclined        = errors.New("authorization_declined")
	ErrBadVerificationCode = errors.New("bad_verification_code")
	ErrExpiredToken        = errors.New("expired_token")
)

func deviceCodeFlow(timeout time.Duration) (*graphClient, error) {
	e := fmt.Sprintf(
		"https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode",
		tenantID,
	)
	data := url.Values{
		"client_id": {clientID},
		"scope":     scopes,
		"tenant":    {tenantID},
	}
	client := &http.Client{}
	// initiate deviceCode authentication
	resp, err := client.PostForm(
		e,
		data,
	)
	if err != nil {
		return nil, err
	}
	b, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		// parse response as GraphErr
		var ae *AuthErr
		if err := json.Unmarshal(b, &ae); err != nil {
			return nil, err
		}
		if ae.Error == "invalid_client" {
			return nil, errors.New(ae.ErrorDescription)
		}
	}
	// http.StatusOK == True so parse as successful response
	var dcr DeviceCodeResponse
	if err := json.Unmarshal(b, &dcr); err != nil {
		return nil, err
	}
	// Print instructions to user
	fmt.Println(dcr.Message)
	// Calculate how long user has to finish auth
	// In reality, user has 15 min but we'll stop polling after timeout.Minutes()
	// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code#device-authorization-request
	fmt.Printf("You have %d minutes to finish authenticating...\n", int(timeout.Minutes()))
	var gc *graphClient
	// number of seconds to delay between each retry attempt
	delayPerAttempt := time.Second * time.Duration(dcr.Interval)
	err = retry.Do(
		func() error {
			data = url.Values{
				"tenant":        {tenantID},
				"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
				"client_id":     {clientID},
				"client_secret": {clientSecret},
				"device_code":   {dcr.DeviceCode},
			}
			tu := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
			// Poll Microsoft to see if authenication flow is complete
			resp, err = client.PostForm(
				tu,
				data,
			)
			b, _ = ioutil.ReadAll(resp.Body)
			var dcpe DeviceCodePollingError
			if err := json.Unmarshal(b, &dcpe); err != nil {
				return err
			}
			// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code#device-authorization-request
			switch dcpe.Error {
			case "authorization_pending":
				// This is the only error for which we will retry
				return ErrAuthPending
			case "authorization_declined":
				return ErrAuthDeclined
			case "bad_verification_code":
				return ErrBadVerificationCode
			case "expired_token":
				return ErrExpiredToken
			}
			if dcpe.Error != "" {
				return errors.New(dcpe.Error)
			}
			// We received no errors
			fmt.Println("Authentication successful!")
			var t Token
			if err := json.Unmarshal(b, &t); err != nil {
				return err
			}
			// Set gc
			gc, err = NewGraphClient(t.Wrapped())
			if err != nil {
				return err
			}
			return nil
		},
		retry.Delay(delayPerAttempt),
		retry.Attempts(uint(timeout.Seconds())/uint(delayPerAttempt.Seconds())),
		// FixedDelay instead of exponential backoff
		retry.DelayType(retry.FixedDelay),
		// Only retry if auth is pending. All other errors are hopeless.
		retry.RetryIf(func(err error) bool {
			return err == ErrAuthPending
		}),
	)
	if err != nil {
		return nil, err
	}
	if gc == nil {
		return nil, errors.New("graphClient is nil, this is bad")
	}
	return gc, nil
}

func main() {
	c, err := deviceCodeFlow(time.Minute * 3)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := c.GetBlob(blobContainer, "azureblobtest")
	if err != nil {
		log.Fatal(err)
	}
	b, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(b))
}