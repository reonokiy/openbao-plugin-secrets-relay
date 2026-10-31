# Configuration writes may carry management credentials. Grant to operators only.
path "vendor-a/config" {
  capabilities = ["read", "update"]
}

path "vendor-a/providers" {
  capabilities = ["list"]
}

path "vendor-a/roles" {
  capabilities = ["list"]
}

path "vendor-a/roles/*" {
  capabilities = ["read", "update", "delete"]
}
