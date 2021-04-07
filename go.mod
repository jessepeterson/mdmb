module github.com/jessepeterson/mdmb

go 1.13

require (
	github.com/go-kit/kit v0.10.0
	github.com/google/uuid v1.2.0
	github.com/groob/plist v0.0.0-20190114192801-a99fbe489d03
	github.com/jessepeterson/cfgprofiles v0.1.0
	github.com/micromdm/scep/v2 v2.0.1-0.20210330040640-fa847cef3c45
	go.etcd.io/bbolt v1.3.3
	go.mozilla.org/pkcs7 v0.0.0-20200128120323-432b2356ecb1
	golang.org/x/sys v0.0.0-20201119102817-f84b799fce68 // indirect
)

replace go.mozilla.org/pkcs7 v0.0.0-20200128120323-432b2356ecb1 => github.com/omorsi/pkcs7 v0.0.0-20210217142924-a7b80a2a8568
