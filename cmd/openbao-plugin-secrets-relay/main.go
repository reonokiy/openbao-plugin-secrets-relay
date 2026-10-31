package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"

	relay "github.com/reonokiy/openbao-plugin-secrets-relay"
)

func main() {
	meta := new(api.PluginAPIClientMeta)
	if err := meta.FlagSet().Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: relay.Factory,
		TLSProviderFunc:    api.VaultPluginTLSProvider(meta.GetTLSConfig()),
		Logger:             hclog.NewNullLogger(),
	}); err != nil {
		// SDK errors can include sensitive upstream diagnostics.
		_, _ = os.Stderr.WriteString("Relay plugin failed; diagnostics withheld\n")
		os.Exit(1)
	}
}
