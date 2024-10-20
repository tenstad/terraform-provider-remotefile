package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccResourceRemoteFile(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
				resource "remote_file" "resource_1" {
					conn {
						host = "remotehost"
						user = "root"
						sudo = true
						password = "password"
						timeout = 1000
					}
					path = "/tmp/resource_1.txt"
					content = "resource_1"
					permissions = "0777"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"remote_file.resource_1", "content", regexp.MustCompile("resource_1")),
				),
			},
		},
	})
}

func TestAccResourceRemoteFileWithDefaultConnection(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
				resource "remote_file" "resource_2" {
					provider = remotehost

					path = "/tmp/resource_2.txt"
					content = "resource_2"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"remote_file.resource_2", "id", regexp.MustCompile("remotehost:22:/tmp/resource_2.txt")),
					resource.TestMatchResourceAttr(
						"remote_file.resource_2", "content", regexp.MustCompile("resource_2")),
				),
			},
		},
	})
}

func TestAccResourceRemoteFileWithAgent(t *testing.T) {
	if os.Getenv("SKIP_TEST_AGENT") == "1" {
		return
	}

	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
				resource "remote_file" "resource_3" {
					conn {
						host = "remotehost"
						user = "root"
						agent = true
					}
					path = "/tmp/resource_3.txt"
					content = "resource_3"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"remote_file.resource_3", "content", regexp.MustCompile("resource_3")),
				),
			},
		},
	})
}

func TestAccResourceRemoteFileOwnership(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
				resource "remote_file" "resource_4" {
					conn {
						host = "remotehost"
						user = "root"
						sudo = true
						password = "password"
					}
					path = "/tmp/resource_4.txt"
					content = "resource_4"
					permissions = "0777"
					owner = "1000"
					group = "1001"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"remote_file.resource_4", "owner_name", regexp.MustCompile("")),
					resource.TestMatchResourceAttr(
						"remote_file.resource_4", "group_name", regexp.MustCompile("")),
					resource.TestMatchResourceAttr(
						"remote_file.resource_4", "owner", regexp.MustCompile("1000")),
					resource.TestMatchResourceAttr(
						"remote_file.resource_4", "group", regexp.MustCompile("1001")),
				),
			},
		},
	})
}

func TestAccResourceRemoteFileOwnershipWithDefaultConnection(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
				resource "remote_file" "resource_5" {
					provider = remotehost
					path = "/tmp/resource_5.txt"
					content = "resource_5"
					owner = "1000"
					group = "1001"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"remote_file.resource_5", "owner_name", regexp.MustCompile("")),
					resource.TestMatchResourceAttr(
						"remote_file.resource_5", "group_name", regexp.MustCompile("")),
					resource.TestMatchResourceAttr(
						"remote_file.resource_5", "owner", regexp.MustCompile("1000")),
					resource.TestMatchResourceAttr(
						"remote_file.resource_5", "group", regexp.MustCompile("1001")),
				),
			},
		},
	})
}

func TestAccResourceRemoteFileOwnershipNames(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
				resource "remote_file" "resource_6" {
					conn {
						host = "remotehost"
						user = "root"
						sudo = true
						password = "password"
					}
					path = "/tmp/resource_6.txt"
					content = "resource_6"
					permissions = "0777"
					owner_name = "root"
					group_name = "root"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"remote_file.resource_6", "owner_name", regexp.MustCompile("root")),
					resource.TestMatchResourceAttr(
						"remote_file.resource_6", "group_name", regexp.MustCompile("root")),
					resource.TestMatchResourceAttr(
						"remote_file.resource_6", "owner", regexp.MustCompile("")),
					resource.TestMatchResourceAttr(
						"remote_file.resource_6", "group", regexp.MustCompile("")),
				),
			},
		},
	})
}
