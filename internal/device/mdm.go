package device

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/groob/plist"
)

func (c *MDMClient) authenticate(ctx context.Context) error {
	ar := &AuthenticationRequest{
		DeviceName:  c.Device.ComputerName,
		MessageType: "Authenticate",
		Topic:       c.MDMPayload.Topic,
		UDID:        c.Device.UDID,

		// non-required fields
		SerialNumber: c.Device.Serial,
	}

	return c.checkinRequest(ctx, ar)
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
	USEnglishDescription string `plist:",omitempty"`
}

type ConnectRequest struct {
	UDID        string
	CommandUUID string `plist:",omitempty"`
	Status      string
	ErrorChain  []ErrorChain `plist:",omitempty"`

	RequestType string `plist:",omitempty"`
}

// type ConnectResponse struct {
// 	Command     interface{}
// 	CommandUUID string
// }

func (c *MDMClient) MdmSignature(ctx context.Context, body []byte) (string, error) {
	return c.transport.SignMessage(ctx, body)
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

// PlistReader encodes i into XML Plist and returns a reader.
func PlistReader(i interface{}) (io.Reader, error) {
	buf := new(bytes.Buffer)
	enc := plist.NewEncoder(buf)
	enc.Indent("\t")
	err := enc.Encode(i)
	return buf, err
}

func (c *MDMClient) checkinRequest(ctx context.Context, i interface{}) error {
	r, err := PlistReader(i)
	if err != nil {
		return err
	}

	resp, err := c.transport.DoCheckIn(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("checkin request failed with HTTP status: %s", resp.Status)
	}

	return nil
}

func (c *MDMClient) TokenUpdate(ctx context.Context, addl string) error {
	tu := &TokenUpdateRequest{
		MessageType: "TokenUpdate",
		PushMagic:   "fakePushMagic" + addl,
		Token:       []byte("fakeToken" + addl),
		Topic:       c.MDMPayload.Topic,
		UDID:        c.Device.UDID,
	}
	return c.checkinRequest(ctx, tu)
}

type ConnectResponseCommand struct {
	RequestType string
}

type ConnectResponse struct {
	Command     ConnectResponseCommand
	CommandUUID string
}

func (c *MDMClient) Connect(ctx context.Context) error {
	req := &ConnectRequest{
		UDID:   c.Device.UDID,
		Status: "Idle",
	}
	return c.connect(ctx, req)
}

func (c *MDMClient) connect(ctx context.Context, connReq interface{}) error {
	if !c.enrolled() {
		return errors.New("device not enrolled")
	}

	r, err := PlistReader(connReq)
	if err != nil {
		return err
	}

	res, err := c.transport.DoReportResultsAndFetchNextCommand(ctx, r)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	respBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("connect request failed with HTTP status: %s", res.Status)
	}

	if len(respBytes) == 0 {
		return nil
	}

	resp := &ConnectResponse{}
	err = plist.Unmarshal(respBytes, &resp)
	if err != nil {
		return err
	}

	nextConnReq, err := c.handleMDMCommand(ctx, resp.Command.RequestType, resp.CommandUUID, respBytes)
	if err != nil {
		log.Println(err)
		nextConnReq = &ConnectRequest{
			UDID:        c.Device.UDID,
			CommandUUID: resp.CommandUUID,
			RequestType: resp.Command.RequestType,
			Status:      "Error",
			ErrorChain: []ErrorChain{
				{
					ErrorCode:            99998,
					ErrorDomain:          "mdmb-handle-mdm-command",
					LocalizedDescription: "Error handling MDM command",
				},
			},
		}
	}

	if nextConnReq == nil {
		fmt.Println("empty response from handling MDM command")
		nextConnReq = &ConnectRequest{
			UDID:        c.Device.UDID,
			CommandUUID: resp.CommandUUID,
			RequestType: resp.Command.RequestType,
			Status:      "Error",
			ErrorChain: []ErrorChain{
				{
					ErrorCode:            99999,
					ErrorDomain:          "mdmb-handle-mdm-command",
					LocalizedDescription: "Empty response from hanlding MDM command",
				},
			},
		}
	}

	return c.connect(ctx, nextConnReq)
}
