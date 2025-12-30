module github.com/zero-day-ai/gibson-tools-official/pkg

go 1.24.4

require github.com/zero-day-ai/sdk v0.0.0

replace github.com/zero-day-ai/sdk => /tmp/build-test/sdk

replace github.com/zero-day-ai/gibson => /tmp/build-test/gibson
