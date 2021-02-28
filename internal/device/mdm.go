package device

import (
	"bytes"
	"encoding/base64"
	"errors"
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
	if c.IdentityCertificate == nil || c.IdentityPrivateKey == nil {
		return "", errors.New("device identity invalid")
	}
	signedData, err := pkcs7.NewSignedData(body)
	if err != nil {
		return "", err
	}
	signedData.AddSigner(c.IdentityCertificate, c.IdentityPrivateKey, pkcs7.SignerInfoConfig{})
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

type ConnectResponseCommand struct {
	RequestType string
}

type ConnectResponse struct {
	Command     ConnectResponseCommand
	CommandUUID string
}

func (c *MDMClient) Connect() error {
	req := &ConnectRequest{
		UDID:   c.Device.UDID,
		Status: "Idle",
	}
	return c.connect(req)
}

func (c *MDMClient) connect(connReq *ConnectRequest) error {
	if !c.enrolled() {
		return errors.New("device not enrolled")
	}

	plistBytes, err := plist.Marshal(connReq)
	if err != nil {
		return err
	}

	mdmSig, err := c.mdmP7Sign(plistBytes)
	if err != nil {
		return err
	}

	client := &http.Client{}
	req, err := http.NewRequest("PUT", c.MDMPayload.ServerURL, bytes.NewReader(plistBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Mdm-Signature", mdmSig)

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("Checkin Request failed with HTTP status: %d", res.StatusCode)
	}

	respBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if len(respBytes) == 0 {
		return nil
	}

	resp := &ConnectResponse{}
	err = plist.Unmarshal(respBytes, &resp)
	if err != nil {
		return err
	}

	var cmdResp *ConnectRequest
	err = c.handleMDMCommand(resp.Command.RequestType, resp.CommandUUID, respBytes)
	if err != nil {
		fmt.Println(err)
		cmdResp = &ConnectRequest{
			UDID:        c.Device.UDID,
			CommandUUID: resp.CommandUUID,
			Status:      "Error",
			ErrorChain: []ErrorChain{
				{
					ErrorCode:            99999,
					ErrorDomain:          "Unknown command",
					LocalizedDescription: "Unknown command",
					USEnglishDescription: "Unknown command",
				},
			},
		}
	} else {
		cmdResp = &ConnectRequest{
			UDID:        c.Device.UDID,
			CommandUUID: resp.CommandUUID,
			Status:      "Acknowledged",
		}

	}

	return c.connect(cmdResp)
}

func (c *MDMClient) handleMDMCommand(reqType, commandUUID string, _ []byte) error {
	return fmt.Errorf("not handling %s command (command UUID %s\n", reqType, commandUUID)
}
