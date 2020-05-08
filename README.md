# Vault client written in golang - WIP

This application connects to a [HashiCorp](https://hashicorp.com) [Vault](https://vaultproject.io) cluster using the [github/hashicorp/vault/api](https://godoc.org/github.com/hashicorp/vault/api) package and retrieves a kv v2 secret.

## Usage

```
vgc
-auth string
    Auth method. (token|approle)
-role_id string
    AppRole Auth Role ID.
-secret_id string
    AppRole Auth Secret ID.
-vault_addr string
    Vault Address (may also be specified via VAULT_ADDR environment variable)
-vault_path string
    Path in Vault from which to retrieve the secret
-vault_token string
    Vault Token (may also be specified via VAULT_TOKEN environment variable)

```

For example:

```
$  vgc -vault_path kv/data/demo/app2 -auth token
INFO: vault_addr is https://vault.service.consul:8200
INFO: auth is token
INFO: vault_path is kv/data/demo/app2

Requested secret at path kv/data/demo/app2:
	api_token → E5145E36-F180-477A-BF56-E63DFC9D15BB
	foo → bar
	service_name → widget
```

```
$  vgc -vault_path kv/data/demo/app2 \
     -auth approle \
     -role_id 01234567-890a-bcde-f012-34567890abcd \
     -secret_id a0123456-7890-abcd-ef01-234567890abc

INFO: vault_addr is https://vault.service.consul:8200
INFO: auth is approle
INFO: vault_path is kv/data/demo/app2

Requested secret at path kv/data/demo/app2:
	service_name → widget
	api_token → E5145E36-F180-477A-BF56-E63DFC9D15BB
	foo → bar
```

## Compiling

Built using go 1.13.5.

```
go get github.com/hashicorp/vault/api
go build
```
