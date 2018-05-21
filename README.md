[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-services-auth.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-services-auth)
[![Build status](https://ci.appveyor.com/api/projects/status/r40u6x9iahfbfvlm/branch/master?svg=true)](https://ci.appveyor.com/project/tochka/virgil-services-auth/branch/master)

# Virgil Auth v4.0

VirgilAuth 4.0 focuses on client developer simplicity while providing specific authorization flows for web applications,
desktop applications, mobile phones, and living room devices. This specification is being developed within the Virgil
Security, Inc. and is based on the OAuth2.0 proposal.
![scheme](https://github.com/VirgilSecurity/virgil-services-auth/blob/master/doc/scheme.png)



## Topics
* [Key Terms](#key-terms)
* [General Information](#general-information)
* [Endpoints](#endpoints)
    * [POST /v5/authorization-grant/actions/get-challenge-message](#post-v5authorization-grantactionsget-challenge-message)
    * [POST /v5/authorization-grant/{authorization_grant_id}/actions/acknowledge](#post-v5authorization-grantauthorization_grant_idactionsacknowledge)
    * [POST /v5/authorization/actions/obtain-access-token](#post-v5authorizationactionsobtain-access-token)
    * [POST /v5/authorization/actions/refresh-access-token](#post-v5authorizationactionsrefresh-access-token)
    * [POST /v5/authorization/actions/verify](#post-v5authorizationactionsverify)
* [Get in start](#get-in-start)
    * [Prepare](#prepare)
    * [Install](#install)
    * [Usage](#usage)
    * [Settings](#settings)
* [Health checker](#health-checker)
    * [GET /v5/health/status](#get-v5healthstatus)
    * [GET /v5/health/info](#get-v5healthinfo)
* [Appendix A. Response codes](#appendix-a-response-codes)
* [Appendix B. Environment](#appendix-b-environment)
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



## Endpoints

In order to obtain an `Access Token` the client / third-party application initiates an `Authorization Grant` process
that includes 3 way handshake process described in PPP Challenge Handshake Authentication Protocol (CHAP) proposal.



### POST /v5/authorization-grant/actions/get-challenge-message

To issue an `Authorization Grant` token for a `Client` it's necessary to make sure that the `Client` is valid. A 3 way
handshake process is used for these purposes. The endpoint requires a `resource_owner_virgil_card_id` request parameter
that identifies the `Resource Owner`'s `Virgil Card` that must be a signed of trustee service (by default is Vigil Key service's card).

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



### POST /v5/authorization-grant/{authorization_grant_id}/actions/acknowledge

Acknowledges that `Resource Owner` holds valid Private Key and receives an `Authorization Grant` code in response.
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



### POST /v5/authorization/actions/obtain-access-token

The endpoint purpose is to exchange an `Authorization Grant` code from the previous step on a valid `Access Token`.

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
    "expires_in": 3600,
    "token_type": "bearer"
}
```

> NOTE: "expires_in" parameter is measured by seconds


### POST /v5/authorization/actions/refresh-access-token

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
    "expires_in": 3600
}
```
>NOTE: "expires_in" parameter measured in seconds

### POST /v5/authorization/actions/verify

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
    "resource_owner_virgil_card_id": "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853"
}
```

# Get in start

## Prepare

Install [mongodb](https://www.mongodb.com)

## Install

Visit [Docker Hub](https://hub.docker.com/r/virgilsecurity/virgil-auth/) see all available images and tags.

## Usage

Make sure that you run mongodb service with default port. Run the docker container by following commands

```
# Pull image from Docker Hub.
$ docker pull virgilsecurity/virgil-auth


# Use `docker run` for the first time.
$ docker run --name=virgil-auth -p 80:8080 --net host -e APP_ID="{YOUR_VIRGIL_APP_ID}" -e API_KEY_ID="{YOUR_VIRGIL_API_KEY_ID}" -e API_KEY="{YOUR_VIRGIL_API_KEY}" -e KEY="{VIRGIL_AUTH_PRIVATE_KEY}" virgilsecurity/virgil-auth

# Use `docker start` if you have stopped it.
$ docker start virgil-auth
```

To test:
```
$ curl http://localhost/v5/health/status -v
```

## Settings

Most of settings are obvious and easy to understand, but some parameters needed more detailed description:
- *APP_ID:* ID of your Application at [Virgil Dashboard](https://dashboard.virgilsecurity.com)
- *API_KEY_ID:* A unique string value that identifies your account at the Virgil developer portal
- *API_KEY:* A Private Key that is used to sign API calls to Virgil Services. For security, you will only be shown the API Private Key when the key is created. Don't forget to save it in a secure location for the next step (You'll use your API Key that was created at Virgil Dashboard. For security purposes, you have to generate JWT on your server side.)
- *Cards address:* It's address of Virgil [cards service](https://developer.virgilsecurity.com/docs/api-reference/card-service/v5). It provides interface to search user's card.
- *Authority card:* It's a card whose signature we trust. If this parameter is set up then a client's card **must** have signature of the authority. The parameter contains of two values: card ID card and public key

Full list of parameters in [Appendix B. Environment](#appendix-b-environment).

# Health checker

## GET /v5/health/status

This endpoint is used to get status of Virgil Auth service.
Return StatusOK (200) if the service work correctly otherwise return StatusBadRequest(400)

## GET /v5/health/info

This endpoint is used to get info of dependencies of Virgil Auth service.

Response:
```
{
  "mongo":{
    "status":200,
    "latency": 1,
  }  
}
```
**Note:** Status parameter can take value 200 or 400. Latency parameter is measured in milliseconds

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
53000 - The resource owner id validation failed
53010 - The Virgil card specified by id doesn't exist on the Virgil Card service
53011 - The Auth service cannot get access to the Virgil card specified by id. The card in application scope and can't be retrieved
53020 - Encrypted message validation failed
53030 - The authentication attempt instance has expired already
53040 - Grant type is not supported
53050 - Unable to find an authorization attempt by the specified authorization grant id
53060 - An authorization grant code has expired already
53070 - An authorization grant code was used previously
53080 - The Access token is invalid
53090 - The Refresh token not found
53100 - The Resource owner's Virgil card not verified
```

# Appendix B. Environment
Command line arguments (prefix: --)| Environment name | Description
---|---|---
db | DB | Connection string to mongodb (`by default 127.0.0.1:27017/virgil-auth`) |
api-key-id | API_KEY_ID | A unique string value that identifies your account at the Virgil developer portal (`required`)
api-key | API_KEY | A Private Key that is used to sign API calls to Virgil Services. (`required`)
api-key-password | API_KEY_PASSWORD | Passphrase for the API key
app-id | APP_ID | ID of your Application at Virgil Dashboard (`required`)
virgil-api-address | VIRGIL_API_ADDRESS | Address of Virgil cloud (`by default https://api.virgilsecurity.com`)
key | KEY | Private key for response signing and message decryption (`required`) |
key-password | KEY_PASSWORD | Passphrase for the private key |
address| ADDRESS | Virgil Auth service address (`by default :8080`)
authority-id | AUTHORITY_ID | Authority card id (`by default used Virgil Cards Service ID`)
authority-pubkey | AUTHORITY_PUBKEY | Authority public key (`by default used Virgil Cards Service Public key`)

# Appendix C. Links
The service was inspired by OAuth 2.0 and CHAP as a handshake protocol
* [OAuth2.0 RFC](http://tools.ietf.org/html/rfc6749)
* [PPP Challenge Handshake Authentication Protocol (CHAP)](https://tools.ietf.org/html/rfc1994)
