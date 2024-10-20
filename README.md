# Terraform Provider Remote

**Documentation**: https://registry.terraform.io/providers/tenstad/remote/latest/docs/resources/file

## Issues

Please create an issue if you find typos, have any questions, or problems with
the provider. Feature requests are welcome, but you may have to get your hands
dirty and take part in the implementation to get the feature merged.

## Pull Requests

Pull requests are welcome! 😊 You may create an issue to discuss the changes
first, but it is not a strict requirement.

Before creating a PR, please ensure that all documentation is correctly
generated (`go generate`), and that go modules are tidy (`go mod tidy`).

## Developing the Provider

### Requirements

If you wish to work on the provider, you'll first need Go installed on your
machine. You might also want Terraform and Docker, depending on the work.

- [Go](https://golang.org/doc/install) >= 1.22
- [Terraform](https://www.terraform.io/downloads.html) >= 0.15.x
- [Docker](https://www.docker.com/get-started) (for test purposes)

### Development Workflow

The playground enables developers to play around with changes and new features
without releasing a new version of the provider.

In `playground/`:

- `make install` to compile and install the provider in the playground
- `make hosts` to start containers to use as remote hosts
- Optionally use `export TF_LOG=INFO` and
  `tflog.Info(ctx, "message from provider")` to log from the provider.
- Evaluate your changes my modifying `main.tf`  
  and running `terraform plan` or `terraform apply`
- `docker exec -it remotehost sh` to enter remote host  
  and see that configuration is applied correctly
- `make clean` to delete terraform state and remote hosts

When changes are working as intended:

- Create/modify acceptance tests
- `make test` to run acceptance test  
  NOTE: A container runtime is required, tests are performed between containers.
- `go generate` to generate documentation
