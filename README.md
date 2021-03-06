# vgc - WIP [![CircleCI](https://circleci.com/gh/ykhemani/vgc.svg?style=svg)](https://circleci.com/gh/ykhemani/vgc)

This little app was written to become more familiar with [go](https://golang.org/) as well as with the [github/hashicorp/vault/api](https://godoc.org/github.com/hashicorp/vault/api) package. It uses this package to connect to a [HashiCorp](https://hashicorp.com) [Vault](https://vaultproject.io) cluster. It is not meant to be a reference app.

## Usage

```
$ ./vgc -h
Usage: ./vgc
  -auth string
    	Auth method - token, approle, ldap, userpass. (default "token")
  -password string
    	Vault password if using ldap or userpass auth.
  -role_id string
    	AppRole Auth Role ID.
  -secret_id string
    	AppRole Auth Secret ID.
  -username string
    	Vault username if using ldap or userpass auth.
  -vault_addr string
        Vault Address (may also be specified via VAULT_ADDR environment variable)
  -secret_path string
    	Path in Vault from which to retrieve the secret.
  -vault_token string
        Vault Token if using token auth (may also be specified via VAULT_TOKEN environment variable)
```

For example:

```
$  vgc -secret_path kv/data/demo/app2 -auth token
INFO: vault_addr is https://vault.service.consul:8200
INFO: auth is token
INFO: secret_path is kv/data/demo/app2

Requested secret at path kv/data/demo/app2:
	api_token → E5145E36-F180-477A-BF56-E63DFC9D15BB
	foo → bar
	service_name → widget
```

```
$  vgc -secret_path kv/data/demo/app2 \
     -auth approle \
     -role_id 01234567-890a-bcde-f012-34567890abcd \
     -secret_id a0123456-7890-abcd-ef01-234567890abc

INFO: vault_addr is https://vault.service.consul:8200
INFO: auth is approle
INFO: secret_path is kv/data/demo/app2

Requested secret at path kv/data/demo/app2:
	service_name → widget
	api_token → E5145E36-F180-477A-BF56-E63DFC9D15BB
	foo → bar
```

## Compiling

Tested using go 1.13.5.

```
go get github.com/hashicorp/vault/api
go build
```
