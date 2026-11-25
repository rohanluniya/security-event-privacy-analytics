# OpenBao 2.7.3 (MPL-2.0 open-source Vault fork) configuration for cryptographic tokenization,
# HMAC master key rotation, and per-subject crypto-shredding key storage.

ui = false
disable_mlock = true

storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

telemetry {
  prometheus_retention_time = "24h"
  disable_hostname          = true
}

# Bootstrap operations (executed by operator or init job in distributed profile):
# 1. bao secrets enable -path=transit transit
# 2. bao write -f transit/keys/secops-hmac-master type=aes256-gcm96 exportable=false auto_rotate_period=720h
# 3. bao secrets enable -path=subject-keys kv-v2
# 4. Subject GDPR erasure deletes subject-keys/metadata/<principal_token> to crypto-shred
#    linkage between tokenized analytics and restricted raw evidence.
