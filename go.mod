module github.com/jessepeterson/mdmb

go 1.13

require (
	github.com/fxamacker/cbor/v2 v2.4.0
	github.com/go-kit/kit v0.10.0
	github.com/google/uuid v1.3.0
	github.com/groob/plist v0.0.0-20220217120414-63fa881b19a5
	github.com/jessepeterson/cfgprofiles v0.1.0
	github.com/mholt/acmez v1.1.1
	github.com/micromdm/scep/v2 v2.1.0
	github.com/smallstep/certinfo v1.11.0
	go.etcd.io/bbolt v1.3.6
	go.mozilla.org/pkcs7 v0.0.0-20210730143726-725912489c62
	go.step.sm/crypto v0.30.0
)

replace github.com/jessepeterson/cfgprofiles => ./../cfgprofiles // TODO: remove the replace
