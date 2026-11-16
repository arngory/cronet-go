module github.com/sagernet/cronet-go/test

go 1.26.0

require (
	github.com/miekg/dns v1.1.72
	github.com/quic-go/quic-go v0.64.1
	github.com/sagernet/cronet-go v0.0.0
	github.com/sagernet/sing v0.8.9
	github.com/stretchr/testify v1.12.1
	go.uber.org/goleak v1.3.0
	golang.org/x/crypto v0.54.0
)

require (
	github.com/ebitengine/purego v0.10.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
)

replace github.com/sagernet/cronet-go => ../
