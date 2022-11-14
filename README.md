# `oidc`

Use me to retrieve an id token.

Guiding principles from https://joshuatcasey.medium.com/who-wants-an-oidc-cli-524afb3c34c4.

```shell
git clone https://github.com/joshuatcasey/oidc.git
cd oidc
go run main.go retrieve \
  --issuerUri=<your-issuer-uri> \
  --clientId=<your-client-id> \
  --clientSecret=<your-client-secret> \
  --port=<port> # Optional, defaults to 8080
```

This assumes the following:

* `<your-issuer-uri>/.well-known/openid-configuration` exists and contains the following information as per [OpenID Connect Discovery 1.0 §3 OpenID Provider Metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#rfc.section.3)
  * `authorization_uri`
  * `token_uri`
  * `jwks_uri`
* A client has been configured in your authorization server with the following properties:
  * Client ID: `<your-client-id>`
  * Client Secret: `<your-client-secret>`
  * Redirect URI: `http://localhost:<port>`
  * Scopes include `openid` (see https://auth0.com/docs/get-started/apis/scopes/openid-connect-scopes#standard-claims)