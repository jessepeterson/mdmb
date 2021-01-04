package mdmclient

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/groob/plist"
	"go.mozilla.org/pkcs7"
)

func (c *MDMClient) authenticate() error {
	ar := &AuthenticationRequest{
		DeviceName:  c.Device.ComputerName,
		MessageType: "Authenticate",
		Topic:       c.MDMPayload.Topic,
		UDID:        c.Device.UDID,

		// non-required fields
		SerialNumber: c.Device.Serial,
	}

	return c.checkinRequest(ar)
}

// AuthenticationRequest ...
type AuthenticationRequest struct {
	BuildVersion string `plist:",omitempty"`
	DeviceName   string
	IMEI         string `plist:",omitempty"`
	MEID         string `plist:",omitempty"`
	MessageType  string
	Model        string `plist:",omitempty"`
	ModelName    string `plist:",omitempty"`
	OSVersion    string `plist:",omitempty"`
	ProductName  string `plist:",omitempty"`
	SerialNumber string `plist:",omitempty"`
	Topic        string
	UDID         string
	EnrollmentID string `plist:",omitempty"` // macOS 10.15 and iOS 13.0 and later
}

type ErrorChain struct {
	ErrorCode            int
	ErrorDomain          string
	LocalizedDescription string
	USEnglishDescription string
}

type ConnectRequest struct {
	UDID        string
	CommandUUID string `plist:",omitempty"`
	Status      string
	ErrorChain  []ErrorChain `plist:",omitempty"`
}

// type ConnectResponse struct {
// 	Command     interface{}
// 	CommandUUID string
// }

// Generates "SignMessage" HTTP header data
func (c *MDMClient) mdmP7Sign(body []byte) (string, error) {
	signedData, err := pkcs7.NewSignedData(body)
	if err != nil {
		return "", err
	}
	signedData.AddSigner(c.Device.IdentityCertificate, c.Device.IdentityPrivateKey, pkcs7.SignerInfoConfig{})
	signedData.Detach()
	sig, err := signedData.Finish()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

type TokenUpdateRequest struct {
	AwaitingConfiguration bool   `plist:",omitempty"`
	EnrollmentID          string `plist:",omitempty"` // macOS 10.15 and iOS 13.0 and later
	EnrollmentUserID      string `plist:",omitempty"` // macOS 10.15 and iOS 13.0 and later
	MessageType           string
	NotOnConsole          bool `plist:",omitempty"`
	PushMagic             string
	Token                 []byte
	Topic                 string
	UDID                  string
	UnlockToken           []byte `plist:",omitempty"`
	UserShortName         string `plist:",omitempty"`
	UserID                string `plist:",omitempty"`
	UserLongName          string `plist:",omitempty"`
}

func (c *MDMClient) checkinRequest(i interface{}) error {
	plistBytes, err := plist.Marshal(i)
	if err != nil {
		return err
	}

	mdmSig, err := c.mdmP7Sign(plistBytes)
	if err != nil {
		return err
	}

	client := &http.Client{}
	req, err := http.NewRequest("PUT", c.MDMPayload.CheckInURL, bytes.NewReader(plistBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Mdm-Signature", mdmSig)

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("Checkin request failed with HTTP status: %d", res.StatusCode)
	}

	return nil
}

func (c *MDMClient) tokenUpdate() error {
	tu := &TokenUpdateRequest{
		MessageType: "TokenUpdate",
		PushMagic:   "fakePushMagic",
		Token:       []byte("fakeToken"),
		Topic:       c.MDMPayload.Topic,
		UDID:        c.Device.UDID,
	}

	return c.checkinRequest(tu)
}

// func Connect(device *device.Device, url string) error {
// 	i := &ConnectRequest{
// 		UDID:   device.UDID,
// 		Status: "Idle",
// 	}

// 	plistBytes, err := plist.Marshal(i)
// 	if err != nil {
// 		return err
// 	}

// 	mdmSig, err := mdmP7Sign(plistBytes, device.IdentityCertificate, device.IdentityPrivateKey)
// 	if err != nil {
// 		return err
// 	}

// 	client := &http.Client{}
// 	req, err := http.NewRequest("PUT", url, bytes.NewReader(plistBytes))
// 	if err != nil {
// 		return err
// 	}
// 	req.Header.Set("Mdm-Signature", mdmSig)

// 	res, err := client.Do(req)
// 	if err != nil {
// 		return err
// 	}
// 	defer res.Body.Close()

// 	xat, err := ioutil.ReadAll(res.Body)
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println("===> Connect")
// 	fmt.Println(res.Header)
// 	fmt.Println(string(xat))
// 	fmt.Println("===> Connect")

// 	if res.StatusCode != 200 {
// 		return fmt.Errorf("Checkin Request failed with HTTP status: %d", res.StatusCode)
// 	}

// 	return nil
// }
