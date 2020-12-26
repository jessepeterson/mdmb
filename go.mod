module github.com/jessepeterson/mdmb

go 1.13

require (
	github.com/go-kit/kit v0.10.0
	github.com/google/uuid v1.1.2
	github.com/groob/plist v0.0.0-20190114192801-a99fbe489d03
	github.com/jessepeterson/cfgprofiles v0.0.0-20201209172704-598005e95a89
	github.com/micromdm/scep v1.0.1-0.20201110133952-f3adbb75202b
	go.mozilla.org/pkcs7 v0.0.0-20200128120323-432b2356ecb1
	golang.org/x/net v0.0.0-20201209123823-ac852fbbde11 // indirect
)

replace github.com/jessepeterson/cfgprofiles => ../../../../../cfgprofiles
