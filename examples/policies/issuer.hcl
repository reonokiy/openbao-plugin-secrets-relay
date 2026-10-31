# Replace vendor-a and dev with the reviewed mount and role.
# The authenticated token must also have an OpenBao identity entity.
path "vendor-a/issue/dev" {
  capabilities = ["update"]
}
