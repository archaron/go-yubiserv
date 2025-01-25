# go-yubiserv

[![license](https://img.shields.io/github/license/archaron/go-yubiserv.svg)](https://github.com/archaron/go-yubiserv/blob/main/LICENSE)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/archaron/go-yubiserv)](https://pkg.go.dev/mod/github.com/archaron/go-yubiserv)
[![GitHub Workflow Status](https://github.com/archaron/go-yubiserv/actions/workflows/go.yml/badge.svg)](https://github.com/archaron/go-yubiserv/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/archaron/go-yubiserv)](https://goreportcard.com/report/github.com/archaron/go-yubiserv)
![Go version](https://img.shields.io/github/go-mod/go-version/archaron/go-yubiserv?style=flat&label=Go%20%3E%3D)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Farcharon%2Fgo-yubiserv.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Farcharon%2Fgo-yubiserv?ref=badge_shield)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Farcharon%2Fgo-yubiserv.svg?type=small)](https://app.fossa.com/projects/git%2Bgithub.com%2Farcharon%2Fgo-yubiserv?ref=badge_large)

Service for Yubikey local validation. Supports SQLite and Hashicorp Valut keystores.


## Command line parameters and environment variables 

| Command line arg          | Environment variable  | Default value          | Description                                                                   |
|---------------------------|-----------------------|------------------------|-------------------------------------------------------------------------------|
| --config value, -c value  | YSR_CONFIG            | config.yaml            | Configuration file name                                                       |
| --debug, -d               | YSR_DEBUG             | false                  | Enable debug log messages                                                     |
| --log-format              | YSR_LOGGER_FORMAT     | console                | Log format: console/json                                                      |
| --api-address value       | YSR_API_ADDRESS       | :8433                  | Validation API bind address                                                   |
| --api-timeout value       | YSR_API_TIMEOUT       | 1s                     | Validation API connect/read timeout                                           |
| --api-secret value        | YSR_API_SECRET        |                        | Base64-encoded string for HMAC signature verification, empty to disable check |
| --api-tls-cert value      | YSR_TLS_CERT          |                        | Validation API TLS certificate file path. If empty, will use HTTP mode        |
| --api-tls-key value       | YSR_TLS_KEY           |                        | Validation API TLS private key file path. If empty, will use HTTP mode        |
| --keystore value          | YSR_KEYSTORE          | vault                  | Key store: vault/sqlite                                                       |
| --sqlite-dbpath value     | YSR_SQLITE_DBPATH     | yubiserv.db            | SQLite3 database path                                                         |
| --vault-address value     | YSR_VAULT_ADDRESS     | https://127.0.0.1:8200 | Vault server address                                                          |
| --vault-role-id value     | YSR_VAULT_ROLE_ID     |                        | role_id for Vault auth, overrides role-file                                   |
| --vault-role-file value   | YSR_VAULT_ROLE_FILE   | role_id                | Path to file containing role_id for Vault auth                                |
| --vault-secret-id value   | YSR_VAULT_SECRET_ID   |                        | secret_id for Vault auth, overrides secret-id                                 |
| --vault-secret-file value | YSR_VAULT_SECRET_FILE | secret_id              | Path to file containing secret_id for Vault auth                              |
| --vault-path              | YSR_VAULT_PATH        | secret/data/yubiserv   | Vault path to KV secrets store                                                |

## Vault key store details
All secrets are kept in vault KV storage:

path: 
```{vault-path}/<public-id>```
Example: ```secret/data/yubiserv/vvcccciiktcv```

data: 
```json
{
  "aes_key": "1234567890abcdef0123456789abcdef",
  "private_id": "01234567890a"
}
```
Both AES key and private identifier can be randomly generated with yubikey manager when creating new OTP slot.

## SQLite3 key store details

```yubiserv generate --start 1 --count 3```

Can be used to generate some keys. Use ```--save``` argument to generate and save to DB.

... TODO ...

## Typical usage:
### SQLite3 key store in HTTPS TLS mode
```yubiserv --keystore=sqlite --api-secret=ynS/XoXc2gwGDBssYSu2w21Aky4= --api-tls-key=./yubiserv.key.pem --api-tls-cert=./yubiserv.cert.pem```

### Vault key store in plain HTTP mode
```yubiserv --api-secret=ynS/XoXc2gwGDBssYSu2w21Aky4= --vault-address=https://127.0.0.1:8200 --vault-path="secret/service/yubiserv"```


## Configuration file example (not required)
```yaml
shutdown_timeout: 30s
api:
  address: :8443
  secret: ynS/XoXc2gwGDBssYSu2w21Aky4=
  timeout: 1s
  tls_cert: ./fullchain.pem
  tls_key: ./privkey.pem

logger:
  color: true
  format: console
  full_caller: false
  level: debug
  no_disclaimer: true
  sampling:
    initial: 100
    thereafter: 100
  trace_level: fatal

vault:
  address: https://127.0.0.1:8200
  role_file: role_id
  secret_file: secret_id
```

