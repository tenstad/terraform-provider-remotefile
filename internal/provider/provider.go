package provider

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure RemoteProvider satisfies various provider interfaces.
var _ provider.Provider = &RemoteProvider{}
var _ provider.ProviderWithFunctions = &RemoteProvider{}

// RemoteProvider defines the provider implementation.
type RemoteProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// RemoteProviderModel describes the provider data model.
type RemoteProviderModel struct {
	Connection  types.List  `tfsdk:"conn"`
	MaxSessions types.Int64 `tfsdk:"max_sessions"`
}

func (p *RemoteProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "remote"
	resp.Version = p.version
}

func (p *RemoteProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Blocks: map[string]schema.Block{
			"conn": schema.ListNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"host": schema.StringAttribute{
							Required: true,
							//FIXME: ForceNew:    true,
							MarkdownDescription: "The remote host.",
						},
						"port": schema.Int64Attribute{
							Optional: true,
							//FIXME: Default:     22,
							//FIXME: ForceNew:    true,
							MarkdownDescription: "The ssh port on the remote host.",
						},
						"timeout": schema.Int64Attribute{
							Optional:            true,
							MarkdownDescription: "The maximum amount of time, in milliseconds, for the TCP connection to establish. Timeout of zero means no timeout.",
						},
						"user": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The user on the remote host.",
						},
						"sudo": schema.BoolAttribute{
							Optional: true,
							//FIXME: Default:     false,
							MarkdownDescription: "Use sudo to gain access to file.",
						},
						"agent": schema.BoolAttribute{
							Optional: true,
							//FIXME: Default:     false,
							MarkdownDescription: "Use a local SSH agent to login to the remote host.",
						},
						"password": schema.StringAttribute{
							Optional:            true,
							Sensitive:           true,
							MarkdownDescription: "The pasword for the user on the remote host.",
						},
						"private_key": schema.StringAttribute{
							Optional:            true,
							Sensitive:           true,
							MarkdownDescription: "The private key used to login to the remote host.",
						},
						"private_key_path": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "The local path to the private key used to login to the remote host.",
						},
						"private_key_env_var": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "The name of the local environment variable containing the private key used to login to the remote host.",
						},
					},
				},
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				MarkdownDescription: "Default connection to host where files are located. Can be overridden in resources and data sources.",
			},
		},
		Attributes: map[string]schema.Attribute{
			"max_sessions": schema.Int64Attribute{
				MarkdownDescription: "Maximum number of open sessions in each host connection.",
				Optional:            true,
				//FIXME: Default:     3,
			},
		},
	}
}

func (p *RemoteProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data RemoteProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client := apiClient{
		resourceData:   &data,
		maxSessions:    int(data.MaxSessions.ValueInt64()),
		mux:            &sync.Mutex{},
		remoteClients:  map[string]*RemoteClient{},
		activeSessions: map[string]int{},
	}

	resp.DataSourceData = &client
	resp.ResourceData = &client
}

func (p *RemoteProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewFileResource,
	}
}

func (p *RemoteProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewFileDataSource,
	}
}

func (p *RemoteProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

// FIXME:
// func (p *RemoteProvider) ConfigValidators(ctx context.Context) []provider.ConfigValidator {
// 	return []provider.ConfigValidator{}
// }

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &RemoteProvider{
			version: version,
		}
	}
}

// FIXME:
// func init() {

// 	// Customize the content of descriptions when output. For example you can add defaults on
// 	// to the exported descriptions if present.
// 	schema.SchemaDescriptionBuilder = func(s *schema.Schema) string {
// 		desc := s.Description
// 		if s.Default != nil {
// 			desc += fmt.Sprintf(" Defaults to `%v`.", s.Default)
// 		}
// 		return strings.TrimSpace(desc)
// 	}
// }

type apiClient struct {
	resourceData   *RemoteProviderModel
	mux            *sync.Mutex
	remoteClients  map[string]*RemoteClient
	activeSessions map[string]int
	maxSessions    int
}

func ConnAs(ctx context.Context, conn types.List) (*ConnectionResourceModel, diag.Diagnostics) {
	connections := []ConnectionResourceModel{}
	if diag := conn.ElementsAs(ctx, &connections, false); diag.HasError() {
		return nil, diag
	}

	if len(connections) > 0 {
		return &connections[0], nil
	}

	return nil, nil
}

func (c *apiClient) getConnWithDefault(ctx context.Context, conn types.List) (*ConnectionResourceModel, diag.Diagnostics) {
	connection, dia := ConnAs(ctx, conn)
	if dia.HasError() {
		return nil, dia
	}
	if connection != nil {
		return connection, dia
	}

	c.mux.Lock()
	defer c.mux.Unlock()

	connection, dia = ConnAs(ctx, c.resourceData.Connection)
	if dia.HasError() {
		return nil, dia
	}
	if connection != nil {
		return connection, dia
	}

	dia.AddError(
		"Configuration error",
		"neither the provider nor the resource/data source have a configured connection",
	)
	return nil, dia
}

func (c *apiClient) getRemoteClient(ctx context.Context, conn *ConnectionResourceModel) (*RemoteClient, diag.Diagnostics) {
	connectionID := conn.ConnectionHash()

	defer c.mux.Unlock()
	for {
		c.mux.Lock()

		if client, ok := c.remoteClients[connectionID]; ok {
			if c.activeSessions[connectionID] >= c.maxSessions {
				c.mux.Unlock()
				continue
			}
			c.activeSessions[connectionID]++

			return client, nil
		}

		client, dia := remoteClientFromResourceData(ctx, conn)
		if dia.HasError() {
			return nil, dia
		}

		c.remoteClients[connectionID] = client
		c.activeSessions[connectionID] = 1
		return client, nil
	}
}

func remoteClientFromResourceData(ctx context.Context, conn *ConnectionResourceModel) (*RemoteClient, diag.Diagnostics) {
	host, clientConfig, dia := conn.Connection()
	if dia.HasError() {
		return nil, dia
	}
	return NewRemoteClient(host, clientConfig)
}

func (c *apiClient) closeRemoteClient(conn *ConnectionResourceModel) diag.Diagnostics {
	connectionID := conn.ConnectionHash()

	c.mux.Lock()
	defer c.mux.Unlock()

	c.activeSessions[connectionID]--
	if c.activeSessions[connectionID] == 0 {
		client := c.remoteClients[connectionID]
		delete(c.remoteClients, connectionID)
		if err := client.Close(); err != nil {
			return diag.Diagnostics{diag.NewErrorDiagnostic("Remote Client Error", err.Error())}
		}
	}

	return nil
}

func getResourceID(d *FileResourceModel, conn *ConnectionResourceModel) string {
	return fmt.Sprintf("%s:%d:%s",
		conn.Host.ValueString(),
		conn.Port.ValueInt64(),
		d.Path.ValueString(),
	)
}
