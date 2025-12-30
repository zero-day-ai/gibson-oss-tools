module github.com/zero-day-ai/gibson-tools-official/execution/impacket

go 1.24.4

require (
	github.com/zero-day-ai/gibson-tools-official/pkg v0.0.0
	github.com/zero-day-ai/sdk v0.0.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/zero-day-ai/gibson v0.0.0-00010101000000-000000000000 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.78.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/zero-day-ai/sdk => /tmp/build-test/sdk

replace github.com/zero-day-ai/gibson => /tmp/build-test/gibson

replace github.com/zero-day-ai/gibson-tools-official/pkg => ../../pkg
