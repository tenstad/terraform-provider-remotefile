package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSourceRemoteFile(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			writeFileToHost("remotehost:22", "/tmp/data_1.txt", "data_1", "root", "bob")
		},
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
				data "remote_file" "data_1" {
					conn {
						host = "remotehost"
						user = "root"
						password = "password"
					}
					path = "/tmp/data_1.txt"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"data.remote_file.data_1", "id", regexp.MustCompile("remotehost:22:/tmp/data_1.txt")),
					resource.TestMatchResourceAttr(
						"data.remote_file.data_1", "content", regexp.MustCompile("data_1")),
					resource.TestMatchResourceAttr(
						"data.remote_file.data_1", "permissions", regexp.MustCompile("0644")),
					resource.TestMatchResourceAttr(
						"data.remote_file.data_1", "owner", regexp.MustCompile("1000")),
					resource.TestMatchResourceAttr(
						"data.remote_file.data_1", "group", regexp.MustCompile("0")),
					resource.TestMatchResourceAttr(
						"data.remote_file.data_1", "owner_name", regexp.MustCompile("bob")),
					resource.TestMatchResourceAttr(
						"data.remote_file.data_1", "group_name", regexp.MustCompile("root")),
				),
			},
		},
	})
}

func TestAccDataSourceRemoteFileOverridingDefaultConnection(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			writeFileToHost("remotehost2:22", "/tmp/data_2.txt", "data_2", "root", "root")
		},
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
				data "remote_file" "data_2" {
					provider = remotehost
					conn {
						host = "remotehost2"
						user = "root"
						password = "password"
					}
					path = "/tmp/data_2.txt"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"data.remote_file.data_2", "content", regexp.MustCompile("data_2")),
				),
			},
		},
	})
}

func TestAccDataSourceRemoteFilePrivateKey(t *testing.T) {
	if os.Getenv("SKIP_TEST_PRIVATE_KEY") == "1" {
		return
	}

	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			writeFileToHost("remotehost:22", "/tmp/data_3.txt", "data_3", "root", "root")
		},
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
				data "remote_file" "data_3" {
					conn {
						host = "remotehost"
						user = "root"
						private_key = <<-EOT
						-----BEGIN OPENSSH PRIVATE KEY-----
						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
						-----END OPENSSH PRIVATE KEY-----
						EOT
					}
					path = "/tmp/data_3.txt"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"data.remote_file.data_3", "content", regexp.MustCompile("data_3")),
				),
			},
		},
	})
}

func TestAccDataSourceRemoteFilePrivateKeyPath(t *testing.T) {
	if os.Getenv("SKIP_TEST_PRIVATE_KEY_PATH") == "1" {
		return
	}

	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			writeFileToHost("remotehost:22", "/tmp/data_4.txt", "data_4", "root", "root")
		},
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
				data "remote_file" "data_4" {
					conn {
						host = "remotehost"
						user = "root"
						private_key_path = "../../tests/key"
					}
					path = "/tmp/data_4.txt"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"data.remote_file.data_4", "content", regexp.MustCompile("data_4")),
				),
			},
		},
	})
}
