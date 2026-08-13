backend "file" {
  path = "/vault/data"
}

default_lease_ttl = "20m"
max_lease_ttl     = "30m"
api_addr = "http://vault:8200"
plugin_directory = "/vault/plugins"
log_level = "debug"
