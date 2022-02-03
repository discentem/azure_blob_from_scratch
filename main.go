package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/StackExchange/wmi"
	retry "github.com/avast/retry-go"
)

var (
	// ErrWMIEmptyResult indicates a condition where WMI failed to return the expected values.
	ErrWMIEmptyResult = errors.New("WMI returned without error, but zero results")
)

type Win32_Bios struct {
	SerialNumber string
}

func Win32Bios() (*Win32_Bios, error) {
	var result []Win32_Bios
	if err := wmi.Query(wmi.CreateQuery(&result, ""), &result); err != nil {
		return nil, err
	}
	if len(result) < 1 {
		return nil, ErrWMIEmptyResult
	}
	return &result[0], nil
}

type Win32_ComputerSystem struct {
	DNSHostName  string
	Domain       string
	DomainRole   int
	Model        string
	Manufacturer string
}

func Win32CompSys() (*Win32_ComputerSystem, error) {
	var result []Win32_ComputerSystem
	if err := wmi.Query(wmi.CreateQuery(&result, ""), &result); err != nil {
		return nil, err
	}
	if len(result) < 1 {
		return nil, ErrWMIEmptyResult
	}
	return &result[0], nil
}

type MDM_DevDetail_Ext01 struct {
	DeviceHardwareData string
}

func MDMDevDetail() (*MDM_DevDetail_Ext01, error) {
	var result []MDM_DevDetail_Ext01
	if err := wmi.QueryNamespace(wmi.CreateQuery(&result, ""), &result, "root/cimv2/mdm/dmmap"); err != nil {
		return nil, err
	}
	if len(result) < 1 {
		return nil, ErrWMIEmptyResult
	}
	return &result[0], nil
}

type autopilotReq struct {
	Manufacturer       string
	Model              string
	SerialNumber       string
	DeviceHardwareData string
}

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

// GetBlob retrieves a blob from Azure Blob container by providing required headers
// and finally calling graphClient.Do()
func (c *graphClient) GetBlob(container, blob string) (*http.Response, error) {
	uri := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", storageAccount, container, blob)
	log.Printf("requesting %s", uri)
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("x-ms-version", "2019-12-12")
	uts := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Add("Date", uts)
	return c.Do(req)
}

type AutopilotState struct {
	ODataType            string `json:"@odata.type"`
	DeviceImportStatus   string `json:"deviceImportStatus"`
	DeviceRegistrationID string `json:"deviceRegistrationId"`
	DeviceErrorCode      int    `json:"deviceErrorCode"`
	DeviceErrorName      string `json:"deviceErrorName"`
}

func (c *graphClient) RegisterAutopilotDevice(apr autopilotReq) error {
	data, err := json.Marshal(struct {
		ODataType         string         `json:"@odata.type"`
		SerialNumber      string         `json:"serialNumber"`
		HardwareIdentifer string         `json:"hardwareIdentifier"`
		State             AutopilotState `json:"state"`
	}{
		ODataType:         "#microsoft.graph.importedWindowsAutopilotDeviceIdentity",
		SerialNumber:      apr.SerialNumber,
		HardwareIdentifer: apr.DeviceHardwareData,
		State: AutopilotState{
			ODataType:          "microsoft.graph.importedWindowsAutopilotDeviceIdentityState",
			DeviceImportStatus: "pending",
			DeviceErrorCode:    0,
		},
	})
	if err != nil {
		return err
	}
	req, _ := http.NewRequest("POST", "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities/", bytes.NewBuffer(data))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(resp.StatusCode)
	fmt.Println(resp.Status)
	fmt.Println(string(body))
	return nil

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
			fmt.Println(dcpe)
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
		retry.Attempts(uint(50)),
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
	// resp, err := c.GetBlob(blobContainer, blobName)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// b, _ := ioutil.ReadAll(resp.Body)
	// fmt.Printf("Printing contents of %s\n", blobName)
	// fmt.Println(string(b))

	apr := autopilotReq{}

	cs, err := Win32CompSys()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	apr.Manufacturer = strings.TrimSpace(cs.Manufacturer)
	apr.Model = strings.TrimSpace(cs.Model)

	bios, err := Win32Bios()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	apr.SerialNumber = bios.SerialNumber

	mdmInfo, err := MDMDevDetail()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	apr.DeviceHardwareData = mdmInfo.DeviceHardwareData
	fmt.Println(apr)

	if err := c.RegisterAutopilotDevice(apr); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
