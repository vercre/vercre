# Desktop Wallet

Tauri + React + Typescript

## Getting Started

Launch the Tauri app using:

```bash
pnpm install
pnpm tauri dev
```

or use VS Code debugger with the `Tauri Bundle` launch configuration.

### Issuance

Launch the `vercre-vci/examples/http` server. It runs on port 8080 by default.

Once both the VCI server and Tauri app are running, the issuance process can be initiated by sending a Credential Offer to the wallet.

```bash
# get pre-authorized credential offer from issuance service
RESP=$(curl --json '{
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "holder_id": "normal_user",
        "pre-authorize": true,
        "tx_code_required": true,
        "callback_id": "1234"
    }' \
    http://localhost:8080/invoke)

# send credential offer to wallet (Tauri app)
OFFER=$(echo $RESP | jq '.credential_offer' | jq -r @uri)
open "openid-vc://credential_offer?credential_offer=$OFFER"

# print user pin
echo $RESP | jq '.user_code'
```

The resultant link should look like:

```bash
openid-vc://credential_offer?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22credentials%22%3A%5B%22EmployeeID_JWT%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3Anull%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22authorization_server%22%3Anull%2C%22interval%22%3Anull%2C%22pre-authorized_code%22%3A%22QCZ1WTMmYjNDUjJSQHNTMmRAR3RaU1ZPSkAlaW1TQVo%22%2C%22user_pin_required%22%3Atrue%7D%7D%7D
```

A convenient way to process a credential offer that bypasses the deep link is to use the add-credential form and paste the offer into the input field. This is not the intended end user experience but allows faster shell development and testing.

```bash
# get pre-authorized credential offer from issuance service
RESP=$(curl --json '{
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "holder_id": "normal_user",
        "pre-authorize": true,
        "tx_code_required": true,
        "callback_id": "1234"
    }' \
    http://localhost:8080/invoke)

# paste this JSON into the add-credential form in the Tauri app
echo $RESP | jq '.credential_offer'

# print user pin
echo $RESP | jq '.user_code'
```

### Presentation

Launch the `vercre-vp/examples/http` server. It runs on port 8080 by default.

Once both the VP server and Tauri app are running, the presentation process can be initiated by sending a Presentation Request to the wallet.

```bash
# get presentation request from verification service
RESP=$(curl --json '{
        "purpose": "To verify employment",
        "input_descriptors": [{
            "id": "employment",
            "constraints": {
                "fields": [{
                    "path":["$.type"],
                    "filter": {
                        "type": "string",
                        "const": "EmployeeIDCredential"
                    }
                }]
            }
        }],
        "device_flow": "CrossDevice"
    }' \
    http://localhost:8080/invoke)

# send presentation request to wallet (Tauri app)
REQUEST_URI=$(echo $RESP | jq '.request_uri' | jq -r @uri)
open "openid-vc://request_uri=$REQUEST_URI"
```

The resultant link should look like:

```bash
openid-vc://request_uri=http://localhost:8080/request/R1BjcyojV01ZVjhvY0shayV-c3QyNEV5b1U1S2Eobl4
```

As for the issuance process, there is a convenient form to paste the request URI that bypasses the
deep link. This is not the intended end user experience but allows faster shell development and testing.


## Troubleshooting

### Debuggable Release

To build a "debuggable" release:

```bash
cargo tauri build --debug
```

### MacOS Custom URL Scheme

Following iterations of development, the custom URL scheme may become registered multiple times, including to the wrong binary. Troubleshoot and clean up by using the following commands:

```bash
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"

# List schema bindings:
$LSREGISTER -dump URLSchemeBinding

# Clean up old entries:
$LSREGISTER -kill -r -domain local -domain system -domain user
```

To re-register the URL scheme, run the following from the `tauri` directory:

```bash
cargo tauri build --debug
```

### Hanging Tauri Process

Periodically, the VS Code debugger will exit with an error and leave the Tauri process running. This prevents the app from being run again because the port is in use. To fix, kill the process by running:

```bash
lsof -nP -iTCP:1420 | grep LISTEN | awk '{print($2)}' | xargs -I '{}' kill {}
```

## Updating Dependencies

```bash
# Tauri
pnpm update

# Rust
cargo update
```
