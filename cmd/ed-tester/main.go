package main

import (
	"github.com/cometbft/cometbft-load-test/pkg/loadtest"
	myabciapp "github.com/sameh-farouk/cometbft-custom-tester/pkg/ed"
)

func main() {
	if err := loadtest.RegisterClientFactory("my-abci-app-name", &myabciapp.MyABCIAppClientFactory{}); err != nil {
		panic(err)
	}
	// The loadtest.Run method will handle CLI argument parsing, errors,
	// configuration, instantiating the load test and/or coordinator/worker
	// operations, etc. All it needs is to know which client factory to use for
	// its load testing.
	loadtest.Run(&loadtest.CLIConfig{
		AppName:              "my-load-tester",
		AppShortDesc:         "Load testing application for My ABCI App",
		AppLongDesc:          "Some long description on how to use the tool",
		DefaultClientFactory: "my-abci-app-name",
	})
}
