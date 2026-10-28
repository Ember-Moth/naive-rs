module naive-rs-perf-cronet

go 1.26.0

require (
	github.com/miekg/dns v1.1.72
	github.com/sagernet/cronet-go v0.0.0-20260912104727-0d28acc44093
	github.com/sagernet/cronet-go/lib/darwin_arm64 v0.0.0-20260912104006-c10c03c318db
	github.com/sagernet/sing v0.8.9
)

require (
	github.com/ebitengine/purego v0.10.0 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
)

replace github.com/sagernet/cronet-go => ../../../target/perf/cronet-go-src

replace github.com/sagernet/cronet-go/lib/darwin_arm64 => ../../../target/perf/cronet-go-src/lib/darwin_arm64
