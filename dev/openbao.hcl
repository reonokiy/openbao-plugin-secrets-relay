ui = true
disable_mlock = true
api_addr = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
plugin_directory = "/plugins"

storage "inmem" {}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}
