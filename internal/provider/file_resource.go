package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	tfpath "github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &FileResource{}
var _ resource.ResourceWithImportState = &FileResource{}

func NewFileResource() resource.Resource {
	return &FileResource{}
}

// FileResource defines the resource implementation.
type FileResource struct {
	client *apiClient
}

// FileResourceModel describes the resource data model.
type FileResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Connection  types.List   `tfsdk:"conn"`
	Path        types.String `tfsdk:"path"`
	Content     types.String `tfsdk:"content"`
	Permissions types.String `tfsdk:"permissions"`
	Group       types.String `tfsdk:"group"`
	GroupName   types.String `tfsdk:"group_name"`
	Owner       types.String `tfsdk:"owner"`
	OwnerName   types.String `tfsdk:"owner_name"`
}

func (r *FileResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (r *FileResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
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
							Default:  int64default.StaticInt64(22),
							Computed: true,
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
							Optional:            true,
							Default:             booldefault.StaticBool(false),
							Computed:            true,
							MarkdownDescription: "Use sudo to gain access to file.",
						},
						"agent": schema.BoolAttribute{
							Optional:            true,
							Default:             booldefault.StaticBool(false),
							Computed:            true,
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
				Computed:            true,
				MarkdownDescription: "The ID of this resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"path": schema.StringAttribute{
				MarkdownDescription: "Path to file on remote host.",
				//FIXME: ForceNew:            true,
				Required: true,
			},
			"content": schema.StringAttribute{
				MarkdownDescription: "Content of file.",
				Required:            true,
			},
			"permissions": schema.StringAttribute{
				MarkdownDescription: "Permissions of file (in octal form).",
				Optional:            true,
				Default:             stringdefault.StaticString("0644"),
				Computed:            true,
			},
			"group": schema.StringAttribute{
				MarkdownDescription: "Group ID (GID) of file owner. Mutually exclusive with `group_name`.",
				Optional:            true,
				//FIXME: ConflictsWith:       []string{"group_name"},
			},
			"group_name": schema.StringAttribute{
				MarkdownDescription: "Group name of file owner. Mutually exclusive with `group`.",
				Optional:            true,
				//FIXME: ConflictsWith:       []string{"group"},
			},
			"owner": schema.StringAttribute{
				MarkdownDescription: "User ID (UID) of file owner. Mutually exclusive with `owner_name`.",
				Optional:            true,
				//FIXME: ConflictsWith:       []string{"owner_name"},
			},
			"owner_name": schema.StringAttribute{
				MarkdownDescription: "User name of file owner. Mutually exclusive with `owner`.",
				Optional:            true,
				//FIXME: ConflictsWith:       []string{"owner"},
			},
		},
	}
}

func (r *FileResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	r.client = client
}

func (r *FileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider Error", "Resource has no client.")
		return
	}

	var data FileResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	conn, dia := r.client.getConnWithDefault(ctx, data.Connection)
	if dia.HasError() {
		resp.Diagnostics.Append(dia...)
		return
	}

	resp.Diagnostics.Append(conn.Validate()...)
	resp.Diagnostics.Append(data.Validate()...)
	if resp.Diagnostics.HasError() {
		return
	}

	client, dia := r.client.getRemoteClient(ctx, conn)
	if dia.HasError() {
		resp.Diagnostics.Append(dia...)
		resp.Diagnostics.AddError("Client Error", "unable to open remote client")
		return
	}
	defer func() {
		if dia := r.client.closeRemoteClient(conn); dia.HasError() {
			resp.Diagnostics.Append(dia...)
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to close remote client"))
			return
		}
	}()

	sudo := conn.Sudo.ValueBool()
	content := data.Content.ValueString()
	path := data.Path.ValueString()
	permissions := data.Permissions.ValueString()

	if err := client.WriteFile(ctx, content, path, permissions, sudo); err != nil {
		resp.Diagnostics.AddError("Remote Error", fmt.Sprintf("unable to create remote file: %s", err.Error()))
		return
	}

	if err := client.ChmodFile(path, permissions, sudo); err != nil {
		resp.Diagnostics.AddAttributeError(tfpath.Root("permissions"), "Remote Error", fmt.Sprintf("unable to update remote file: %s", err.Error()))
		return
	}

	if group, ok := data.GroupOk(); ok {
		if err := client.ChgrpFile(path, group, sudo); err != nil {
			resp.Diagnostics.AddError("Remote Error", fmt.Sprintf("unable to change group of remote file: %s", err.Error()))
			return
		}
	}

	if owner, ok := data.OwnerOk(); ok {
		if err := client.ChownFile(path, owner, sudo); err != nil {
			resp.Diagnostics.AddError("Remote Error", fmt.Sprintf("unable to change owner of remote file: %s", err.Error()))
			return

		}
	}

	data.ID = types.StringValue(getResourceID(&data, conn))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *FileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider Error", "Resource has no client.")
		return
	}

	var data FileResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	conn, dia := r.client.getConnWithDefault(ctx, data.Connection)
	if dia.HasError() {
		resp.Diagnostics.Append(dia...)
		return
	}

	resp.Diagnostics.Append(conn.Validate()...)
	resp.Diagnostics.Append(data.Validate()...)
	if resp.Diagnostics.HasError() {
		return
	}

	client, dia := r.client.getRemoteClient(ctx, conn)
	if dia.HasError() {
		resp.Diagnostics.Append(dia...)
		resp.Diagnostics.AddError("Client Error", "unable to open remote client")
		return
	}
	defer func() {
		if dia := r.client.closeRemoteClient(conn); dia.HasError() {
			resp.Diagnostics.Append(dia...)
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to close remote client"))
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

		if !data.Owner.IsNull() && !data.Owner.IsUnknown() {
			owner, err := client.ReadFileOwner(path, sudo)
			if err != nil {
				resp.Diagnostics.AddAttributeError(tfpath.Root("owner"), "Remote Error", fmt.Sprintf("unable to read from remote: %s", err.Error()))
				return
			}
			data.Owner = types.StringValue(owner)
		}
		if !data.OwnerName.IsNull() && !data.OwnerName.IsUnknown() {
			ownerName, err := client.ReadFileOwnerName(path, sudo)
			if err != nil {
				resp.Diagnostics.AddAttributeError(tfpath.Root("owner_name"), "Remote Error", fmt.Sprintf("unable to read from remote: %s", err.Error()))
				return
			}
			data.OwnerName = types.StringValue(ownerName)
		}

		if !data.Group.IsNull() && !data.Group.IsUnknown() {
			group, err := client.ReadFileGroup(path, sudo)
			if err != nil {
				resp.Diagnostics.AddAttributeError(tfpath.Root("group"), "Remote Error", fmt.Sprintf("unable to read from remote: %s", err.Error()))
				return
			}
			data.Group = types.StringValue(group)
		}
		if !data.GroupName.IsNull() && !data.GroupName.IsUnknown() {
			groupName, err := client.ReadFileGroupName(path, sudo)
			if err != nil {
				resp.Diagnostics.AddAttributeError(tfpath.Root("group_name"), "Remote Error", fmt.Sprintf("unable to read from remote: %s", err.Error()))
				return
			}
			data.GroupName = types.StringValue(groupName)
		}
	} else {
		data.ID = types.StringValue("")
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Note: copy-paste of Create (minus setting ID)
func (r *FileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider Error", "Resource has no client.")
		return
	}

	var data FileResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	conn, dia := r.client.getConnWithDefault(ctx, data.Connection)
	if dia.HasError() {
		resp.Diagnostics.Append(dia...)
		return
	}

	resp.Diagnostics.Append(conn.Validate()...)
	resp.Diagnostics.Append(data.Validate()...)
	if resp.Diagnostics.HasError() {
		return
	}

	client, dia := r.client.getRemoteClient(ctx, conn)
	if dia.HasError() {
		resp.Diagnostics.Append(dia...)
		resp.Diagnostics.AddError("Client Error", "unable to open remote client")
		return
	}
	defer func() {
		if dia := r.client.closeRemoteClient(conn); dia.HasError() {
			resp.Diagnostics.Append(dia...)
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to close remote client"))
			return
		}
	}()

	sudo := conn.Sudo.ValueBool()
	content := data.Content.ValueString()
	path := data.Path.ValueString()
	permissions := data.Permissions.ValueString()

	if err := client.WriteFile(ctx, content, path, permissions, sudo); err != nil {
		resp.Diagnostics.AddError("Remote Error", fmt.Sprintf("unable to create remote file: %s", err.Error()))
		return
	}

	if err := client.ChmodFile(path, permissions, sudo); err != nil {
		resp.Diagnostics.AddAttributeError(tfpath.Root("permissions"), "Remote Error", fmt.Sprintf("unable to update remote file: %s", err.Error()))
		return
	}

	if group, ok := data.GroupOk(); ok {
		if err := client.ChgrpFile(path, group, sudo); err != nil {
			resp.Diagnostics.AddError("Remote Error", fmt.Sprintf("unable to change group of remote file: %s", err.Error()))
			return
		}
	}

	if owner, ok := data.OwnerOk(); ok {
		if err := client.ChownFile(path, owner, sudo); err != nil {
			resp.Diagnostics.AddError("Remote Error", fmt.Sprintf("unable to change owner of remote file: %s", err.Error()))
			return
		}
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *FileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider Error", "Resource has no client.")
		return
	}

	var data FileResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	conn, dia := r.client.getConnWithDefault(ctx, data.Connection)
	if dia.HasError() {
		resp.Diagnostics.Append(dia...)
		return
	}

	resp.Diagnostics.Append(conn.Validate()...)
	resp.Diagnostics.Append(data.Validate()...)
	if resp.Diagnostics.HasError() {
		return
	}

	client, dia := r.client.getRemoteClient(ctx, conn)
	if dia.HasError() {
		resp.Diagnostics.Append(dia...)
		resp.Diagnostics.AddError("Client Error", "unable to open remote client")
		return
	}
	defer func() {
		if dia := r.client.closeRemoteClient(conn); dia.HasError() {
			resp.Diagnostics.Append(dia...)
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to close remote client"))
			return
		}
	}()

	sudo := conn.Sudo.ValueBool()
	path := data.Path.ValueString()

	exists, err := client.FileExists(path, sudo)
	if err != nil {
		resp.Diagnostics.AddError("Remote Error", fmt.Sprintf("unable to check if remote file exists: %s", err.Error()))
		return
	}
	if exists {
		if err := client.DeleteFile(path, sudo); err != nil {
			resp.Diagnostics.AddError("Remote Error", fmt.Sprintf("unable to delete remote file: %s", err.Error()))
			return
		}
	}
}

func (r *FileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, tfpath.Root("id"), req, resp)
}

// Validate validates required and defaulted fields
func (m *FileResourceModel) Validate() diag.Diagnostics {
	dia := diag.Diagnostics{}

	// if m.Path.IsNull() || m.Path.IsUnknown() {
	// 	dia.AddAttributeError(tfpath.Root("path"), "Client Error", "Path is unknown")
	// }

	// if m.Content.IsNull() || m.Content.IsUnknown() {
	// 	dia.AddAttributeError(tfpath.Root("content"), "Client Error", "Content is unknown")
	// }

	// if m.Permissions.IsNull() || m.Permissions.IsUnknown() {
	// 	dia.AddAttributeError(tfpath.Root("permissions"), "Client Error", "Permissions is unknown")
	// }

	return dia
}

func (m *FileResourceModel) OwnerOk() (string, bool) {
	if !m.Owner.IsNull() && !m.Owner.IsUnknown() {
		return m.Owner.ValueString(), true
	}
	if !m.OwnerName.IsNull() && !m.OwnerName.IsUnknown() {
		return m.OwnerName.ValueString(), true
	}
	return "", false
}

func (m *FileResourceModel) GroupOk() (string, bool) {
	if !m.Group.IsNull() && !m.Group.IsUnknown() {
		return m.Group.ValueString(), true
	}
	if !m.GroupName.IsNull() && !m.GroupName.IsUnknown() {
		return m.GroupName.ValueString(), true
	}
	return "", false
}
