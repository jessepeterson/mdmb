package device

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sort"

	"github.com/groob/plist"
	"github.com/jessepeterson/cfgprofiles"
	bolt "go.etcd.io/bbolt"
)

type ProfileStore struct {
	ID string

	DB *bolt.DB
}

func NewProfileStore(id string, db *bolt.DB) *ProfileStore {
	return &ProfileStore{ID: id, DB: db}
}

func (ps *ProfileStore) Load(id string) (p *cfgprofiles.Profile, err error) {
	pb := []byte{}
	key := fmt.Sprintf("%s_%s", ps.ID, id)
	err = ps.DB.View(func(tx *bolt.Tx) error {
		pb = BucketGet(tx, "profiles", key)
		return nil
	})
	if err != nil {
		return
	}
	if len(pb) == 0 {
		return nil, fmt.Errorf("missing or zero-length profile: %s", id)
	}
	p = &cfgprofiles.Profile{}
	err = plist.Unmarshal(pb, p)
	return
}

func (ps *ProfileStore) persistProfile(pb []byte, profileID string) error {
	if len(pb) == 0 {
		return errors.New("empty profile")
	}
	key := fmt.Sprintf("%s_%s", ps.ID, profileID)
	return ps.DB.Update(func(tx *bolt.Tx) error {
		return BucketPutOrDelete(tx, "profiles", key, pb)
	})
}

func (ps *ProfileStore) removeProfile(profileID string) error {
	key := fmt.Sprintf("%s_%s", ps.ID, profileID)
	return ps.DB.Update(func(tx *bolt.Tx) error {
		return BucketPutOrDelete(tx, "profiles", key, nil)
	})
}

func (ps *ProfileStore) savePayloadRefString(profileID string, pld *cfgprofiles.Payload, ekey, value string) error {
	return ps.DB.Update(func(tx *bolt.Tx) error {
		key := fmt.Sprintf("%s_%s_%s_%s", profileID, pld.PayloadIdentifier, pld.PayloadUUID, ekey)
		return BucketPutOrDeleteString(tx, "profile_payload_refs", key, value)
	})
}

func (ps *ProfileStore) loadPayloadRefString(profileID string, pld *cfgprofiles.Payload, ekey string) (s string, err error) {
	err = ps.DB.View(func(tx *bolt.Tx) error {
		key := fmt.Sprintf("%s_%s_%s_%s", profileID, pld.PayloadIdentifier, pld.PayloadUUID, ekey)
		s = BucketGetString(tx, "profile_payload_refs", key)
		return nil
	})
	return
}

func (ps *ProfileStore) ListUUIDs() (uuids []string, err error) {
	err = ps.DB.View(func(tx *bolt.Tx) error {
		uuids = BucketGetKeysWithPrefix(tx, "profiles", ps.ID+"_", true)
		return nil
	})
	return
}

func (device *Device) SystemProfileStore() *ProfileStore {
	if device.sysProfileStore == nil {
		device.sysProfileStore = NewProfileStore(device.UDID, device.boltDB)
	}
	return device.sysProfileStore
}

const (
	PayloadRequiresNetwork = 1 << iota
	PayloadRequiresIdentities
)

type payloadAndResult struct {
	CommonPayload        *cfgprofiles.Payload
	PayloadRequiresFlags int
	Payload              interface{}

	// not pretty...
	StringResult        string
	payloadAndResultRef *payloadAndResult
}

func findpayloadAndResultByUUID(plds []*payloadAndResult, uuid string) *payloadAndResult {
	for _, v := range plds {
		if v.CommonPayload != nil && v.CommonPayload.PayloadUUID == uuid {
			return v
		}
	}
	return nil
}

func (device *Device) ValidateProfileInstall(p *cfgprofiles.Profile) error {
	mdmPlds := p.MDMPayloads()
	if len(mdmPlds) >= 1 {
		if len(mdmPlds) > 1 {
			return errors.New("Profile may only contain one MDM payload")
		}
		if device.MDMProfileIdentifier != "" {
			return errors.New("device already enrolled, please unenroll first")
		}
	}
	return nil
}

func classifyAndSortProfilePayloads(p *cfgprofiles.Profile, ascending bool) []*payloadAndResult {
	orderedPayloads := make([]*payloadAndResult, len(p.PayloadContent))
	for i, plc := range p.PayloadContent {
		switch pl := plc.Payload.(type) {
		case *cfgprofiles.SCEPPayload:
			orderedPayloads[i] = &payloadAndResult{
				CommonPayload:        &pl.Payload,
				Payload:              pl,
				PayloadRequiresFlags: PayloadRequiresNetwork,
			}
		case *cfgprofiles.MDMPayload:
			orderedPayloads[i] = &payloadAndResult{
				CommonPayload:        &pl.Payload,
				Payload:              pl,
				PayloadRequiresFlags: PayloadRequiresNetwork | PayloadRequiresIdentities,
			}
		default:
			orderedPayloads[i] = &payloadAndResult{
				CommonPayload: cfgprofiles.CommonPayload(pl),
				Payload:       pl,
			}
		}
	}

	// sort the profiles into installation order
	sort.SliceStable(orderedPayloads, func(i, j int) bool {
		if ascending {
			return orderedPayloads[i].PayloadRequiresFlags > orderedPayloads[j].PayloadRequiresFlags
		} else {
			return orderedPayloads[i].PayloadRequiresFlags < orderedPayloads[j].PayloadRequiresFlags
		}
	})

	return orderedPayloads
}

func (device *Device) InstallProfile(pb []byte) error {
	if len(pb) == 0 {
		return errors.New("empty profile")
	}
	p := &cfgprofiles.Profile{}
	err := plist.Unmarshal(pb, p)
	if err != nil {
		return err
	}
	err = device.ValidateProfileInstall(p)
	if err != nil {
		return err
	}

	orderedPayloads := classifyAndSortProfilePayloads(p, false)

	// process and install payloads
	// TODO: to process profile roll-backs/uninstalls
	for _, pr := range orderedPayloads {
		switch pl := pr.Payload.(type) {
		case *cfgprofiles.SCEPPayload:
			pr.StringResult, err = device.installSCEPPayload(p.PayloadIdentifier, pl)
			if err != nil {
				return err
			}
			if pr.StringResult == "" {
				return errors.New("no result from scep payload install")
			}
		case *cfgprofiles.MDMPayload:
			pr.payloadAndResultRef = findpayloadAndResultByUUID(orderedPayloads, pl.IdentityCertificateUUID)
			if pr.payloadAndResultRef == nil {
				return fmt.Errorf("could not find payload UUID %s", pl.IdentityCertificateUUID)
			}

			if pr.payloadAndResultRef.StringResult == "" {
				return errors.New("referenced identity payload has no result keychain ID")
			}
			device.MDMIdentityKeychainUUID = pr.payloadAndResultRef.StringResult
			device.Save()

			err = device.installMDMPayload(pl, p.PayloadIdentifier)
			if err != nil {
				return err
			}
		default:
			fmt.Printf("unknown payload type %s uuid %s not processed\n", pr.CommonPayload.PayloadType, pr.CommonPayload.PayloadUUID)
		}
	}

	return device.SystemProfileStore().persistProfile(pb, p.PayloadIdentifier)
}

func (device *Device) installMDMPayload(mdmPayload *cfgprofiles.MDMPayload, profileID string) error {
	c, err := newMDMClientUsingPayload(device, mdmPayload)
	if err != nil {
		return err
	}
	err = c.enroll(profileID)
	if err != nil {
		return err
	}

	device.Save()
	return nil
}

// installSCEPPayload ... and returns the keychain identity UUID
func (device *Device) installSCEPPayload(profileID string, scepPayload *cfgprofiles.SCEPPayload) (string, error) {
	key, err := keyFromSCEPProfilePayload(scepPayload, rand.Reader)
	if err != nil {
		return "", err
	}

	csrBytes, err := csrFromSCEPProfilePayload(scepPayload, device, rand.Reader, key)
	if err != nil {
		return "", err
	}

	cert, err := scepNewPKCSReq(csrBytes, scepPayload.PayloadContent.URL, scepPayload.PayloadContent.Challenge)
	if err != nil {
		return "", err
	}

	kciKey := NewKeychainItem(device.SystemKeychain(), ClassKey)
	kciKey.Key = key
	err = kciKey.Save()
	if err != nil {
		return "", err
	}

	kciCert := NewKeychainItem(device.SystemKeychain(), ClassCertificate)
	kciCert.Certificate = cert
	err = kciCert.Save()
	if err != nil {
		return "", err
	}

	kciID := NewKeychainItem(device.SystemKeychain(), ClassIdentity)
	kciID.IdentityKeyUUID = kciKey.UUID
	kciID.IdentityCertificateUUID = kciCert.UUID
	err = kciID.Save()
	if err != nil {
		return "", err
	}

	err = device.SystemProfileStore().savePayloadRefString(profileID, &scepPayload.Payload, "keychain_identity", kciKey.UUID)
	if err != nil {
		return "", err
	}

	return kciID.UUID, nil
}

func (device *Device) RemoveProfile(profileID string) error {
	p, err := device.SystemProfileStore().Load(profileID)
	if err != nil {
		return err
	}
	orderedPayloads := classifyAndSortProfilePayloads(p, true)

	for _, pr := range orderedPayloads {
		switch pr.Payload.(type) {
		// case *cfgprofiles.SCEPPayload:
		case *cfgprofiles.MDMPayload:
			err = device.removeMDMPayload()
			if err != nil {
				return err
			}
		default:
			fmt.Printf("unknown payload type %s uuid %s not processed\n", pr.CommonPayload.PayloadType, pr.CommonPayload.PayloadUUID)
		}
	}

	return device.SystemProfileStore().removeProfile(p.PayloadIdentifier)
}

func (device *Device) removeMDMPayload() error {
	c, err := device.MDMClient()
	if err != nil {
		return err
	}
	err = c.unenroll()
	if err != nil {
		return err
	}
	device.Save()
	return nil
}
