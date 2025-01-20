Diagrama de secuencia de autenticación SAML

```
User               Service Provider (SP)            Identity Provider (IdP)
 |                          |                                |
 |--- Request Resource ---->|                                |
 |                          |                                |
 |                          |---- Redirect to IdP ---------->|
 |                          |<--- SAML Request Form ---------|
 |<-- Redirect to IdP ------|                                |
 |                          |                                |
 |--- SAML Auth Request --->|                                |
 |                          |--- Validate Request ---------->|
 |                          |<--- Authenticate User ---------|
 |                          |                                |
 |<-- SAML Assertion -------|                                |
 |                          |                                |
 |--- Send Assertion ------>|                                |
 |                          |                                |
 |--- Validate Assertion -->|                                |
 |                          |                                |
 |<-- Grant Access ---------|                                |
```