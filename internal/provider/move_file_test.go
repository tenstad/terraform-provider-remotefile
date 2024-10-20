package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Updating fields in provider or swapping provider should ideally be supported
func TestMovingFileByModifyingProvider(t *testing.T) {
	if os.Getenv("SKIP_TEST_MOVE_FILE_BY_MODIFYING_PROVIDER") == "1" {
		return
	}

	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				// Create file on 'remotehost'
				Config: providerConfig + `
				resource "remote_file" "move_file" {
					provider = remotehost
					path = "/tmp/move_file.txt"
					content = "x"
				}
				`,
			},
			{
				// Move file to 'remotehost2'
				Config: providerConfig + `
				resource "remote_file" "move_file" {
					provider = remotehost2
					path = "/tmp/move_file.txt"
					content = "x"
				}
				`,
			},
			{
				// Read file on 'remotehost2'
				Config: providerConfig + `
				resource "remote_file" "move_file" {
					provider = remotehost2
					path = "/tmp/move_file.txt"
					content = "x"
				}
				data "remote_file" "move_file" {
					provider = remotehost2
					path = "/tmp/move_file.txt"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"data.remote_file.move_file", "content", regexp.MustCompile("x")),
				),
			},
		},
	})
}

func TestMovingFileByModifyingConn(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				// Create file on 'remotehost'
				Config: providerConfig + `
				resource "remote_file" "move_file_2" {
					conn {
						host = "remotehost"
						user = "root"
						password = "password"
					}
					path = "/tmp/move_file_2.txt"
					content = "x"
				}
				`,
			},
			{
				// Move file to 'remotehost2'
				Config: providerConfig + `
				resource "remote_file" "move_file_2" {
					conn {
						host = "remotehost2"
						user = "root"
						password = "password"
					}
					path = "/tmp/move_file_2.txt"
					content = "x"
				}
				`,
			},
			{
				// Read file on 'remotehost2'
				Config: providerConfig + `
				resource "remote_file" "move_file_2" {
					conn {
						host = "remotehost2"
						user = "root"
						password = "password"
					}
					path = "/tmp/move_file_2.txt"
					content = "x"
				}
				data "remote_file" "move_file_2" {
					conn {
						host = "remotehost2"
						user = "root"
						password = "password"
					}
					path = "/tmp/move_file_2.txt"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"data.remote_file.move_file_2", "content", regexp.MustCompile("x")),
				),
			},
		},
	})
}
