package main

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"os"
  "flag"
  "log"
)

var vault_addr string = "https://127.0.0.1:8200"
var vault_path string
var vault_token string = "root"
var role_id string
var secret_id string
var auth string = "token"

var VClient *api.Client // global variable

func usage() {
  fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
  flag.PrintDefaults()
}

func vault_connect(vault_addr string) error {
  config := &api.Config{
    Address: vault_addr,
  }

  client, err := api.NewClient(config)
  if err != nil {
    return err
  }
  VClient = client
  return nil
}

func vault_auth_with_token(vault_token string) error {
  VClient.SetToken(vault_token)
  return nil
}

func vault_auth_with_approle(role_id string, secret_id string) error {
  resp, err := VClient.Logical().Write("auth/approle/login",  map[string]interface{}{
    "role_id": role_id,
    "secret_id": secret_id,
  })
  if err != nil {
    log.Fatal(err)
  }

  err = vault_auth_with_token(resp.Auth.ClientToken)
  if err != nil {
    fmt.Println(err)
    return err
  }

//  fmt.Printf("Vault token: %s\n", resp.Auth.ClientToken)
  return nil
}

func vault_read_secret(vault_path string) {
  c := VClient.Logical()
  secret, err := c.Read(vault_path)
  if err != nil {
		fmt.Println(err)
		return
	}

  m, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		fmt.Printf("Error: %T %#v\n", secret.Data["data"], secret.Data["data"])
    return
	}

  fmt.Printf("Requested secret at path %s:\n", vault_path)
  for key, value := range m {
    fmt.Printf("\t%s \u2192 %s\n", key, value)
  }

  return
}

func main() {

  // Parse command line options with default values defined below
	flag.Usage = usage
  flag.StringVar(&vault_addr, "vault_addr", LookupEnvOrString("VAULT_ADDR", vault_addr), "Vault Address")
  flag.StringVar(&vault_token, "vault_token", LookupEnvOrString("VAULT_TOKEN", vault_token), "Vault Token")
  flag.StringVar(&vault_path, "vault_path", LookupEnvOrString("VAULT_PATH", vault_path), "Path in Vault from which to retrieve the secret")
  flag.StringVar(&auth, "auth", LookupEnvOrString("VAULT_AUTH", auth), "Auth method.")
  flag.StringVar(&role_id, "role_id", LookupEnvOrString("VAULT_APPROLE_ROLE_ID", role_id), "AppRole Auth Role ID.")
  flag.StringVar(&secret_id, "secret_id", LookupEnvOrString("VAULT_APPROLE_SECRET_ID", secret_id), "AppRole Auth Secret ID.")

  flag.Parse()

  if vault_addr == "" {
    fmt.Println("Error: No Vault Address specified.\n")
    flag.Usage()
    os.Exit(1)
  }

  if vault_path == "" {
    fmt.Println("Error: No Vault Path specified.\n")
    flag.Usage()
    os.Exit(1)
  }

  fmt.Printf("INFO: vault_addr is %s\n", vault_addr)
  fmt.Printf("INFO: auth is %s\n", auth)
  fmt.Printf("INFO: vault_path is %s\n", vault_path)

  fmt.Printf("\n")

  err := vault_connect(vault_addr)
  if err != nil {
    fmt.Println(err)
    return
  }

  switch auth {
    case "token":
      err = vault_auth_with_token(vault_token)
      if err != nil {
        fmt.Println(err)
        return
      }
    case "approle":
      if (role_id == "" || secret_id == "") {
        fmt.Println("Error: role_id and secret_id must be specified for approle auth.")
        flag.Usage()
        os.Exit(1)
      }
      err = vault_auth_with_approle(role_id, secret_id)
      if err != nil {
        fmt.Println(err)
        return
      }
    default:
      flag.Usage()
      os.Exit(1)
  }

  vault_read_secret(vault_path)

}

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}
