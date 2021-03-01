package device

import (
	"fmt"
	"strings"

	"github.com/groob/plist"
	"github.com/jessepeterson/cfgprofiles"
)

func (c *MDMClient) handleMDMCommand(reqType, commandUUID string, respBytes []byte) (interface{}, error) {
	switch reqType {
	case "DeviceInformation":
		return c.handleDeviceInfo(respBytes)
	case "ProfileList":
		return c.handleProfileList(reqType, commandUUID)
	case "InstallProfile":
		return c.handleInstallProfile(respBytes)
	default:
		fmt.Printf("MDM command not handled: %s UUID %s\n", reqType, commandUUID)
		return &ConnectRequest{
			UDID:        c.Device.UDID,
			CommandUUID: commandUUID,
			RequestType: reqType,
			Status:      "Error",
			ErrorChain: []ErrorChain{
				{
					ErrorCode:            12021,
					ErrorDomain:          "MCMDMErrorDomain",
					LocalizedDescription: fmt.Sprintf("Unknown command: %s <MDMClientError:91>", reqType),
				},
			},
		}, nil
	}
}

type DeviceInfoCommand struct {
	ConnectResponseCommand
	Queries []string
}

type DeviceInfo struct {
	Command     DeviceInfoCommand
	CommandUUID string
}

type DeviceInfoResponse struct {
	ConnectRequest
	QueryResponses map[string]string
}

func (c *MDMClient) handleDeviceInfo(respBytes []byte) (interface{}, error) {
	cmd := &DeviceInfo{}
	err := plist.Unmarshal(respBytes, cmd)
	if err != nil {
		return nil, err
	}
	resp := &DeviceInfoResponse{
		ConnectRequest: ConnectRequest{
			UDID:        c.Device.UDID,
			Status:      "Acknowledged",
			CommandUUID: cmd.CommandUUID,
			RequestType: cmd.Command.RequestType,
		},
		QueryResponses: make(map[string]string),
	}
	// TODO: check MDM enrollment permission bits in all of this?
	queries := cmd.Command.Queries
	if len(queries) == 0 {
		queries = []string{
			"DeviceName",
			"SerialNumber",
			"UDID",
		}
	}
	var unknownQueries []string
	for _, v := range queries {
		switch v {
		case "DeviceName":
			resp.QueryResponses[v] = c.Device.ComputerName
		case "SerialNumber":
			resp.QueryResponses[v] = c.Device.Serial
		case "UDID":
			resp.QueryResponses[v] = c.Device.UDID
		default:
			unknownQueries = append(unknownQueries, v)
		}
	}
	fmt.Printf("unknown DeviceInfo queries: %s\n", strings.Join(unknownQueries, ", "))
	return resp, nil
}

// type ProfileListCommand struct {
// 	ConnectResponseCommand
// 	ManagedOnly                  bool `plist:",omitempty"`
// 	RequestRequiresNetworkTether bool `plist:",omitempty"`
// }

// type ProfileList struct {
// 	Command     ProfileListCommand
// 	CommandUUID string
// }

type ProfileListResponse struct {
	ConnectRequest
	ProfileList []*profileListProfile
}

type profileListProfile struct {
	cfgprofiles.Profile
	// SignerCertificates []...
}

// Reassembles profile payloads with only the generic "common" payload and wraps in profile wrapper struct
func profileForProfileList(p *cfgprofiles.Profile) *profileListProfile {
	genericPayloads := []*cfgprofiles.Payload{}
	for _, v := range p.PayloadContent {
		genericPayloads = append(genericPayloads, cfgprofiles.CommonPayload(v.Payload))
		fmt.Println(genericPayloads)
	}
	newProfile := &profileListProfile{
		Profile: *p,
	}
	newProfile.Profile.PayloadContent = nil
	for _, v := range genericPayloads {
		newProfile.Profile.AddPayload(v)
	}
	return newProfile
}

func (c *MDMClient) handleProfileList(reqType, commandUUID string) (interface{}, error) {
	// since we don't handle any of the custom command members just
	// ignore it for now
	//
	// cmd := &ProfileList{}
	// err := plist.Unmarshal(respBytes, cmd)
	// if err != nil {
	// 	return nil, err
	// }
	resp := &ProfileListResponse{
		ConnectRequest: ConnectRequest{
			UDID:        c.Device.UDID,
			Status:      "Acknowledged",
			CommandUUID: commandUUID,
			RequestType: reqType,
		},
	}
	uuids, err := c.Device.SystemProfileStore().ListUUIDs()
	if err != nil {
		return nil, err
	}
	for _, uuid := range uuids {
		// fmt.Println(uuid)
		p, err := c.Device.SystemProfileStore().Load(uuid)
		if err != nil {
			fmt.Printf("error loading profile: %s\n", err)
		}
		newProfile := profileForProfileList(p)
		resp.ProfileList = append(resp.ProfileList, newProfile)
	}
	return resp, nil
}

type InstallProfileCommand struct {
	ConnectResponseCommand
	Payload                      []byte
	RequestRequiresNetworkTether bool `plist:",omitempty"`
}

type InstallProfile struct {
	Command     InstallProfileCommand
	CommandUUID string
}

type InstallProfileResponse struct {
	ConnectRequest
	RequestType string
}

func (c *MDMClient) handleInstallProfile(respBytes []byte) (interface{}, error) {
	cmd := &InstallProfile{}
	err := plist.Unmarshal(respBytes, cmd)
	if err != nil {
		return nil, err
	}
	err = c.Device.installProfileFromMDM(cmd.Command.Payload)
	if err != nil {
		return nil, err
	}
	resp := &InstallProfileResponse{
		ConnectRequest: ConnectRequest{
			UDID:        c.Device.UDID,
			Status:      "Acknowledged",
			CommandUUID: cmd.CommandUUID,
			RequestType: cmd.Command.RequestType,
		},
	}
	return resp, nil
}
