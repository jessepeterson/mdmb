package device

import (
	"fmt"
	"strings"

	"github.com/groob/plist"
)

func (c *MDMClient) handleMDMCommand(reqType, commandUUID string, respBytes []byte) (interface{}, error) {
	switch reqType {
	case "DeviceInformation":
		return c.handleDeviceInfo(respBytes)
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
