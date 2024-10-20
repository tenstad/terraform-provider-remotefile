package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	tfpath "github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &FileDataSource{}

func NewFileDataSource() datasource.DataSource {
	return &FileDataSource{}
}

// FileDataSource defines the resource implementation.
type FileDataSource struct {
	client *apiClient
}

// FileDataSourceModel describes the resource data model.
type FileDataSourceModel struct {
	FileResourceModel
}

func (d *FileDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (d *FileDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "File on remote host.",

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
							//FIXME: Default:     false
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
				MarkdownDescription: "Connection to host where files are located.",
			},
		},
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The ID of this resource.",
				Computed:            true,
			},
			"path": schema.StringAttribute{
				MarkdownDescription: "Path to file on remote host.",
				Required:            true,
			},
			"content": schema.StringAttribute{
				MarkdownDescription: "Content of file.",
				Computed:            true,
			},
			"permissions": schema.StringAttribute{
				MarkdownDescription: "Permissions of file (in octal form).",
				Computed:            true,
			},
			"group": schema.StringAttribute{
				MarkdownDescription: "Group ID (GID) of file owner.",
				Computed:            true,
			},
			"group_name": schema.StringAttribute{
				MarkdownDescription: "Group name of file owner.",
				Computed:            true,
			},
			"owner": schema.StringAttribute{
				MarkdownDescription: "User ID (UID) of file owner.",
				Computed:            true,
			},
			"owner_name": schema.StringAttribute{
				MarkdownDescription: "User name of file owner.",
				Computed:            true,
			},
		},
	}
}

func (d *FileDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*apiClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *apiClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

func (d *FileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider Error", "Data source has no client.")
		return
	}

	var data FileDataSourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	conn, dia := d.client.getConnWithDefault(ctx, data.Connection)
	if dia.HasError() {
		resp.Diagnostics.Append(dia...)
		return
	}

	resp.Diagnostics.Append(conn.Validate()...)
	resp.Diagnostics.Append(data.Validate()...)
	if resp.Diagnostics.HasError() {
		return
	}

	client, dia := d.client.getRemoteClient(ctx, conn)
	if dia.HasError() {
		resp.Diagnostics.Append(dia...)
		resp.Diagnostics.AddError("Client Error", "unable to open remote client")
		return
	}
	defer func() {
		if dia := d.client.closeRemoteClient(conn); dia.HasError() {
			resp.Diagnostics.Append(dia...)
			resp.Diagnostics.AddError("Client Error", "unable to close remote client")
			return
		}
	}()

	sudo := conn.Sudo.ValueBool()
	path := data.Path.ValueString()

	exists, err := client.FileExists(data.Path.ValueString(), conn.Sudo.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError("Remote Error", fmt.Sprintf("unable to check if remote file exists: %s", err.Error()))
		return
	}
	if exists {
		content, err := client.ReadFile(path, sudo)
		if err != nil {
			resp.Diagnostics.AddAttributeError(tfpath.Root("content"), "Remote Error", fmt.Sprintf("unable to read from remote: %s", err.Error()))
			return
		}
		data.Content = types.StringValue(content)

		permissions, err := client.ReadFilePermissions(path, sudo)
		if err != nil {
			resp.Diagnostics.AddAttributeError(tfpath.Root("permissions"), "Remote Error", fmt.Sprintf("unable to read from remote: %s", err.Error()))
			return
		}
		data.Permissions = types.StringValue(permissions)

		owner, err := client.ReadFileOwner(path, sudo)
		if err != nil {
			resp.Diagnostics.AddAttributeError(tfpath.Root("owner"), "Remote Error", fmt.Sprintf("unable to read from remote: %s", err.Error()))
			return
		}
		data.Owner = types.StringValue(owner)

		ownerName, err := client.ReadFileOwnerName(path, sudo)
		if err != nil {
			resp.Diagnostics.AddAttributeError(tfpath.Root("owner_name"), "Remote Error", fmt.Sprintf("unable to read from remote: %s", err.Error()))
			return
		}
		data.OwnerName = types.StringValue(ownerName)

		group, err := client.ReadFileGroup(path, sudo)
		if err != nil {
			resp.Diagnostics.AddAttributeError(tfpath.Root("group"), "Remote Error", fmt.Sprintf("unable to read from remote: %s", err.Error()))
			return
		}
		data.Group = types.StringValue(group)

		groupName, err := client.ReadFileGroupName(path, sudo)
		if err != nil {
			resp.Diagnostics.AddAttributeError(tfpath.Root("group_name"), "Remote Error", fmt.Sprintf("unable to read from remote: %s", err.Error()))
			return
		}
		data.GroupName = types.StringValue(groupName)
	} else {
		resp.Diagnostics.AddError("Error", "cannot read file, it does not exist")
		return
	}

	data.ID = types.StringValue(getResourceID(&data.FileResourceModel, conn))

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
