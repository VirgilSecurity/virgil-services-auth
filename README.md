# Virgil Auth v4.0

VirgilAuth 4.0 focuses on client developer simplicity while providing specific authorization flows for web applications,
desktop applications, mobile phones, and living room devices. This specification is being developed within the Virgil
Security, Inc. and is based on the OAuth2.0 proposal.
![scheme](https://github.com/VirgilSecurity/virgil-services-auth/blob/master/doc/scheme.png)



## Topics
* [Key Terms](#key-terms)
* [General Information](#general-information)
* [Endpoints](#endpoints)
    * [POST /authorization-grant/actions/get-challenge-message](#post-authorization-grantactionsget-challenge-message)
    * [POST /authorization-grant/{authorization_grant_id}/actions/acknowledge](#post-authorization-grantauthorization-grant-idactionsacknowledge)
    * [POST /authorization/actions/obtain-access-code](#post-authorizationactionsobtain-access-code)
    * [POST /authorization/actions/refresh-access-code](#post-authorizationactionsrefresh-access-code)
    * [POST /authorization/actions/verify](#post-authorizationactionsverify)
* [Environment](#environment)
* [Dependency](#Dependency)
* [Appendix A. Response codes](#appendix-a-response-codes)
* [Appendix B. Environment](#appendix-b-response-sign)
* [Appendix C. Links](#appendix-c-links)



## Key terms:
* `Access Token` is a token that was retrieved in exchange in `Authorization Grant` token. This token can be used by a
`Client` to perform calls to `Resource Server`s that support Virgil Auth authorization. `Access Token`'s lifetime is
limited and it expires in an 10 minutes. In this case a new instance of `Access Token` can be issued by a `Client` directly on
a `Virgil Auth Service` using a `Refresh Token`.
* `Authorization Grant` code is a token that was issued by the `Authorization Server` after a `Handshake procedure`.
This token cannot be used to access `Resource Servers` directly, but needs to be exchanged on a valid `Access Token` on
a */authorization/actions/obtain-access-code* endpoint. `Authorization Grant` is required as an intermediate step to make
it possible to request it by third-party services and bypass it later to the end `Client`. In this case the `Client`
will be the only owner of an `Access Token`.
* `Authorization Server` is a Virgil web-service that issues tokens like `Authorization Grant`, `Access Token` and
 `Refresh Token` and performs `Authorization verification`.
* `Authorization Verification` is an action that is performed by a `Resource Server` when it was requested with a Virgil
`Access Token`. The `Resource Server` performs a call to the `Authorization Server` to make sure that `Access Token` is
valid and allows request to the `Resource`.
* `Client` is a client application that performs requests to protected `Resource`s on `Resource Server`s on behalf of a
`Resource Owner`.
* `Handshake procedure` is a process to identify that both parts of the dialog are authorized.
* `Resource` is a peace of information or an action that can be invoked on a `Resource Server`.
* `Refresh Token` is a utility long-living token that is used to regenerate expired `Access Token`. It's crucial to keep
it safe.
* `Resource Owner` is an actual owner of a Virgil Card and some `Resource`s on `Resource Server`s that are associated
with it.
* `Resource Server` is a web-service that has some protected `Resource`s that are available only for a `Resource Owner`.



## General information
* The service's application identity value is **com.VirgilSecurity.auth**, so the public card can be found on the
 Virgil Card service using */card/{card-id}* endpoint.



## Endpoints

In order to obtain an `Access Token` the client / third-party application initiates an `Authorization Grant` process
that includes 3 way handshake process described in PPP Challenge Handshake Authentication Protocol (CHAP) proposal.



### POST /authorization-grant/actions/get-challenge-message

To issue an `Authorization Grant` token for a `Client` it's necessary to make sure that the `Client` is valid. A 3 way
handshake process is used for these purposes. The endpoint requires a `resource_owner_virgil_card_id` request parameter
that identifies the `Resource Owner`'s `Virgil Card` that must be a signed of trustee service (by default is Vigil Key service's card).
If scope is not set will be used wildcard (\*)

An endpoint invocation encrypts a message for a resource owner.

**Request:**
```json
{
    "resource_owner_virgil_card_id": "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853"
}
```
<!--*FOR FUTURE PURPOSES:*
* **client_id** request parameter to identify Client;
* **scope** request parameter to set an appropriate authorization token scope;
* **redirect_url** request parameter to verify a validity of a Client's request;
* **state** request parameter to prevent CSRF-attacks. This parameters will be returned in the response;
* **request_sign** must be signed with one of Applications that are signed with Virgil Auth service
                   to prevent cases of unauthorized handshakes.
-->
**Response:**
```json
{
    "authorization_grant_id": "58452cf7ce392cc47d42337a",
    "encrypted_message": "eyJpZCI6IjQ0NDQ0NDQ0LTQ0NDQtNDQ0NC00NDQ0LTQ0NDQ0NDQ0NDQ0NCIsImNyZWF0ZWRfYXQiOiIyMDE1LTExLTIzIDEzOjA3OjQ0IiwiZGF0YSI6W10sImlzX2NvbmZpcm1lZCI6dHJ1ZSwicHVibGljX2tleV9pZCI6IjIyMjIyMjIyLTIyMjItMjIyMi0yMjIyLTIyMjIyMjIyMjIyMiIsImlkZW50aXR5X2lkIjoiMzMzMzMzMzMtMzMzMy0zMzMzLTMzMzMtMzMzMzMzMzMzMzMzIn0="
}
```

Encrypted message is some random string that was encrypted for the `resource_owner_virgil_card_id`.



### POST /authorization-grant/{authorization_grant_id}/actions/acknowledge

Acknowledges that `Resource Owner` holds valid Private Key and receives an `Authorization Grant` token in response.
**encrypted_message** is a decrypted message from the previous step and re-encrypted with a Virgil Auth public key.

Request:
```json
{
    "encrypted_message": "MIGZMA0GCWCGSAFlAwQCAgUABIGHMIGEAkBmtz5SCxMjd2mAFN1aZqynga4GfRM/kd01MHIfOQ7s5mNG9AQF5wd54RO8rH2urpiM/zElFp5wDTz8FrTjjcseAkAPjpZLU5e2FLl54RY3Xgb1744Ynvg7EBtPxHejpIHm4e7bhs3dWnvF40KMmweG/FjeeOlL60vj1E6ax0pMvC6Z"
}
```

Response:
```json
{
    "code": "AWC9fIlzRSNt1qGUw8cnh03sj3NbmPKxWVYUNmCmfiY"
}
```

<!--*FOR FUTURE PURPOSES:*
* **scope** request parameter to set an appropriate authorization token scope;
* **state** request parameter to prevent CSRF-attacks. This parameters will be returned in the response;

Scope examples:
com.VirgilSecurity.keys_virgil_card[65bce698-b7be-46d3-941b-66936b235314,05e22b5b-8ff8-410f-b60a-b5347635220b]_*
-->



### POST /authorization/actions/obtain-access-token

The endpoint purpose is to exchange an `Authorization Grant` token from the previous step on a valid `Access Token`.

Request:
```json
{
    "grant_type": "access_code",
    "code": "AWC9fIlzRSNt1qGUw8cnh03sj3NbmPKxWVYUNmCmfiY"
}
```

Response:
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
    "refresh_token": "dBJpvmX8oG52TkBJc7msyh3LuevuQ8JK9sNOp7b2UvY",
    "expires_in": "3600",
    "token_type": "bearer"
}
```



### POST /authorization/actions/refresh-access-token

The endpoint purpose is to generate a new `Access Token` using previously retrieved `Refresh Token`.

Request:
```json
{
    "grant_type": "refresh_token",
    "refresh_token": "dBJpvmX8oG52TkBJc7msyh3LuevuQ8JK9sNOp7b2UvY"
}
```

Response:
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
    "expires_in": "3600"
}
```


### POST /authorization/actions/verify

This endpoint is used by `Resource Server`s to verify an `Access Token` provided as an authorization grant.

Request:
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
}

```
Response:
```json
{
    "resource_owner_virgil_card_id": "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853",
    "scope":"search_global search_app"
}
```

# Environment



# Appendix A. Response codes

**`HTTP error codes`**
Application uses standard HTTP response codes:
```
200 - Success
400 - Request error
404 - Entity not found
405 - Method not allowed
500 - Server error
```

Additional information about the error is returned as JSON-object like:
```
{
    "code": {error-code}
}
```

**`HTTP 500. Server error`** status is returned on internal application errors
```
10000 - Internal application error
```

**`HTTP 400. Request error`** status is returned on request data validation errors
```
53000 - The resource owner uuid validation failed
53010 - The Virgil card specified by Uuid doesn't exist on the Virgil Keys service
53020 - Encrypted message validation failed
53030 - The authentication attempt instance has expired already
53040 - Grant type is not supported as it is outside of the list: ['authorization_code']
53050 - Unable to find an authorization attempt by the specified code
53060 - An authorization code has expired already
53070 - An authorization code was used previously
53080 - The Access code is invalid
53090 - The Refresh token not found
53100 - The Resource owner's Virgil card not verified
```

# Appendix B. Environment
Command line arguments (prefix: --)| Environment name | Description
---|---|---
db | DB | Connection string to mongodb (`by default 127.0.0.1:27017`) |
token | TOKEN | Token to get access to Virgil Cards service (`required`)
host | HOST | Host domain of Cards service (`by default used the Virgil Cards servcie`)
key | KEY | Private key for response signing and message decryption (encoded into bas64) (`required`) |
address| ADDRESS | Auth service address (`by default :8080`)
authid | AUTHID | Authority card id. All client card must be signed the Authority (`by default used Virgil Cards Service ID`)
authpubkey | AUTHPUBKEY | Authority public key (encoded into bas64).  All client card must be signed the Authority (`by default used Virgil Cards Service Public key`)

# Appendix C. Links
The service was inspired by OAuth 2.0 and CHAP as a handshake protocol
* [OAuth2.0 RFC](http://tools.ietf.org/html/rfc6749)
* [PPP Challenge Handshake Authentication Protocol (CHAP)](https://tools.ietf.org/html/rfc1994)
