package provider

import (
	"context"
	"fmt"
	"io/ioutil"

	"github.com/bramvdbogaerde/go-scp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func init() {
	// Set descriptions to support markdown syntax, this will be used in document generation
	// and the language server.
	schema.DescriptionKind = schema.StringMarkdown

	// Customize the content of descriptions when output. For example you can add defaults on
	// to the exported descriptions if present.
	// schema.SchemaDescriptionBuilder = func(s *schema.Schema) string {
	// 	desc := s.Description
	// 	if s.Default != nil {
	// 		desc += fmt.Sprintf(" Defaults to `%v`.", s.Default)
	// 	}
	// 	return strings.TrimSpace(desc)
	// }
}

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			DataSourcesMap: map[string]*schema.Resource{
				"remotefile": dataSourceRemotefile(),
			},
			ResourcesMap: map[string]*schema.Resource{
				"remotefile": resourceRemotefile(),
			},
			Schema: map[string]*schema.Schema{},
		}

		p.ConfigureContextFunc = configure(version, p)

		return p
	}
}

type apiClient struct {
	clientConfig ssh.ClientConfig
	host         string
}

func configure(version string, p *schema.Provider) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(c context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		return &apiClient{}, diag.Diagnostics{}
	}
}

func newClient(d *schema.ResourceData) (*apiClient, error) {
	clientConfig := ssh.ClientConfig{
		User:            d.Get("conn.0.username").(string),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	password, ok := d.GetOk("conn.0.password")
	if ok {
		clientConfig.Auth = append(clientConfig.Auth, ssh.Password(password.(string)))
	}

	private_key, ok := d.GetOk("conn.0.private_key")
	if ok {
		signer, err := ssh.ParsePrivateKey([]byte(private_key.(string)))
		if err != nil {
			return nil, fmt.Errorf("couldn't create a ssh client config from private key: %s", err.Error())
		}
		clientConfig.Auth = append(clientConfig.Auth, ssh.PublicKeys(signer))
	}

	private_key_path, ok := d.GetOk("conn.0.private_key_path")
	if ok {
		content, err := ioutil.ReadFile(private_key_path.(string))
		if err != nil {
			return nil, fmt.Errorf("couldn't read private key: %s", err.Error())
		}
		signer, err := ssh.ParsePrivateKey(content)
		if err != nil {
			return nil, fmt.Errorf("couldn't create a ssh client config from private key file: %s", err.Error())
		}
		clientConfig.Auth = append(clientConfig.Auth, ssh.PublicKeys(signer))
	}

	client := apiClient{
		clientConfig: clientConfig,
		host:         fmt.Sprintf("%s:%d", d.Get("conn.0.host").(string), d.Get("conn.0.port").(int)),
	}

	return &client, nil
}

func (c apiClient) getSSHClient() (*ssh.Client, error) {
	sshClient, err := ssh.Dial("tcp", c.host, &c.clientConfig)
	if err != nil {
		return nil, fmt.Errorf("couldn't establish a connection to the remote server: %s", err.Error())
	}
	return sshClient, nil
}

func (c apiClient) getSCPClient() (*scp.Client, error) {
	scpClient := scp.NewClient(c.host, &c.clientConfig)
	err := scpClient.Connect()
	if err != nil {
		return nil, fmt.Errorf("couldn't establish a connection to the remote server: %s", err.Error())
	}
	return &scpClient, nil
}

func (c apiClient) getSFTPClient() (*sftp.Client, error) {
	sshClient, err := c.getSSHClient()
	if err != nil {
		return nil, err
	}

	sftp, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, err
	}
	return sftp, nil
}
