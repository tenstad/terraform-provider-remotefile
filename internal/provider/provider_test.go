package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

const (
	// providerConfig is a shared configuration to combine with the actual test
	// configuration.
	providerConfig = `
provider "remote" {}

provider "remotehost" {
	conn {
		host     = "remotehost"
		user     = "root"
		password = "password"
		port     = 22
	}
}

provider "remotehost2" {
	conn {
		host     = "remotehost2"
		user     = "root"
		password = "password"
		port     = 22
	}
}
`
)

// providerFactories are used to instantiate a provider during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a provider server to which the CLI can
// reattach.
var providerFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"remote":      providerserver.NewProtocol6WithError(New("test")()),
	"remotehost":  providerserver.NewProtocol6WithError(New("test")()),
	"remotehost2": providerserver.NewProtocol6WithError(New("test")()),
}

func testAccPreCheck(t *testing.T) {
	// You can add code here to run prior to any test case execution, for example assertions
	// about the appropriate environment variables being set are common to see in a pre-check
	// function.
}
