package main

import (
  "flag"
  "fmt"
  "github.com/hashicorp/vault/api"
  "os"
  "log"
  //"reflect"
)

var vault_addr string = "https://127.0.0.1:8200"
var secret_path string

var vault_token string = "root"

var role_id string
var secret_id string

var username string
var password string

var auth string = "token"

var VClient *api.Client

////////////////////////////////////////////////////////////////////////////////
// usage
func usage() {
  fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
  flag.PrintDefaults()
}

////////////////////////////////////////////////////////////////////////////////
// connect to Vault cluster at specified address
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

////////////////////////////////////////////////////////////////////////////////
// Authenticate with Vault using provided token
func vault_auth_with_token(vault_token string) error {
  VClient.SetToken(vault_token)
  return nil
}

////////////////////////////////////////////////////////////////////////////////
// Authenticate with Vault using provided AppRole Role ID and Secret ID
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

//  fmt.Printf("DEBUG: Vault token from approle auth: %s\n", resp.Auth.ClientToken)
  return nil
}

////////////////////////////////////////////////////////////////////////////////
// Authenticate with Vault using LDAP|Userpass|OKTA auth
func vault_auth_with_ldap_userpass_okta(method string, username string, password string) error {
  login_path := "auth/" + method + "/login/" + username
  fmt.Printf("INFO: login path is %s\n",login_path)

  resp, err := VClient.Logical().Write(login_path,  map[string]interface{}{ "password": password })

  if err != nil {
    log.Fatal(err)
  }

  err = vault_auth_with_token(resp.Auth.ClientToken)
  if err != nil {
    fmt.Println(err)
    return err
  }

  // fmt.Printf("Vault token from %s auth: %s\n", method, resp.Auth.ClientToken)

  return nil

}

////////////////////////////////////////////////////////////////////////////////
// Read secret from Vault
func vault_read_secret(secret_path string) {
  c := VClient.Logical()

  fmt.Printf("INFO: Requested secret at path %s:\n", secret_path)

  secret, err := c.Read(secret_path)

  if err != nil {
		fmt.Println("Error reading secret at %s: %v", secret_path, err)
		return
	}

  for key, value := range secret.Data {
    //fmt.Printf("value is of type %s\n", reflect.TypeOf(value))

    switch valueType := value.(type) {
      case string:
        // process kv v1
        fmt.Printf("\t%s \u2192 %s\n", key, value)
      case map[string]interface {}:
        // process kv v2
        if key == "data" {
          m, ok := value.(map[string]interface{})

          if !ok {
            fmt.Printf("Error getting secret data\n")
            return
          }

          for subKey, subValue := range m {
            fmt.Printf("\t%s \u2192 %s\n", subKey, subValue)
          }
        }
      default:
        fmt.Printf("Unexpected value type %v\n", valueType)
    }
  }

  // m, ok := secret.Data["data"].(map[string]interface{})
	// if !ok {
	// 	fmt.Printf("Error getting secret data: %T %#v\n", secret.Data["data"], secret.Data["data"])
  //   return
	// }
  //
  // fmt.Printf("\n\n%v\n\n", m)
  //
  // for key, value := range m {
  //   fmt.Printf("\t%s \u2192 %s\n", key, value)
  // }

  return
}

////////////////////////////////////////////////////////////////////////////////
// Get environment variable or return default
func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

////////////////////////////////////////////////////////////////////////////////
// main
func main() {

  // Parse command line options with default values defined below
	flag.Usage = usage
  flag.StringVar(&vault_addr, "vault_addr", LookupEnvOrString("VAULT_ADDR", vault_addr), "Vault Address")

  flag.StringVar(&vault_token, "vault_token", LookupEnvOrString("VAULT_TOKEN", vault_token), "Vault Token if using token auth.")

  flag.StringVar(&secret_path, "secret_path", LookupEnvOrString("SECRET_PATH", secret_path), "Path in Vault from which to retrieve the secret.")

  flag.StringVar(&auth, "auth", LookupEnvOrString("VAULT_AUTH", auth), "Auth method - token|approle|ldap|okta|userpass.")

  flag.StringVar(&role_id, "role_id", LookupEnvOrString("VAULT_APPROLE_ROLE_ID", role_id), "AppRole Auth Role ID.")
  flag.StringVar(&secret_id, "secret_id", LookupEnvOrString("VAULT_APPROLE_SECRET_ID", secret_id), "AppRole Auth Secret ID.")

  flag.StringVar(&username, "username", "", "Vault username if using ldap or userpass auth.")
  flag.StringVar(&password, "password", "", "Vault password if using ldap or userpass auth.")

  flag.Parse()

  if vault_addr == "" {
    fmt.Println("Error: No Vault Address specified.\n")
    flag.Usage()
    os.Exit(1)
  }

  if secret_path == "" {
    fmt.Println("Error: No Secret Path specified.\n")
    flag.Usage()
    os.Exit(1)
  }

  fmt.Printf("INFO: vault_addr is %s\n", vault_addr)
  fmt.Printf("INFO: auth method is %s\n", auth)
  fmt.Printf("INFO: secret_path is %s\n", secret_path)

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
    case "ldap", "okta", "userpass":
      if (username == "" || password == "") {
        fmt.Printf("Error: username and password must be specified for %s auth.", auth)
        flag.Usage()
        os.Exit(1)
      }
      err = vault_auth_with_ldap_userpass_okta(auth, username, password)
      if err != nil {
        fmt.Println(err)
        return
      }
    default:
      flag.Usage()
      os.Exit(1)
  }

  vault_read_secret(secret_path)

}
