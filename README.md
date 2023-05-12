Spring Security with JWT
========================

JWT(JSON Web Tokens) is very useful for API gateway to authorize the user

# Vocabulary

* Credentials: Prove the principal is correct. This is usually a password, token(key&secret) etc
* Authentication: identify an account, such as UsernamePasswordAuthenticationToken, RememberMeAuthenticationToken, JwtAuthentication.
* XxxAuthenticationFilter: The filter to get Authentication an inject to SecurityContext by SecurityContextHolder.getContext().setAuthentication(authentication)
* XxxAuthenticationProvider: Process a specific Authentication to validate authentication
* Authority: granted authority, such as updateAccount, updateProfile. Please use "ROLE_" prefix to define roles.
* UserDetails: store user information which is later encapsulated into Authentication objects, such as authorities from database

# JWT

* Issuer: issuer, such as domain name, company name or organization name etc.
* Subject: subject, such as email, user id, user nick, mobile etc
* http header:

```
Authorization: Bearer xxx.yyy.zzz
```

### RSA token generation

Almost we use RSA private key to generate JWT token and use RSA public key to verify token.

```
# generate a 2048-bit RSA private key
$ openssl genrsa -out private_key.pem 2048

# convert private Key to PKCS#8 format (so Java can read it)
$ openssl pkcs12 -topk8 -inform PEM -outform DER -in private_key.pem \
    -out private_key.der -nocrypt

# output public key portion in DER format (so Java can read it)
$ openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der

```


```
# generate a 2048-bit RSA private key
$ openssl genrsa -out jwt_private_key.pem 2048

# convert private Key to PKCS#8 format (so Java can read it)
$ openssl pkcs8 -topk8 -inform PEM -outform DER -in jwt_private_key.pem -out jwt_rsa.key -nocrypt

# output public key portion in DER format (so Java can read it)
$ openssl rsa -in jwt_private_key.pem -pubout -outform DER -out jwt_rsa.pub

```


### Attention

* anonymous for actuator and white urls list

# References

* JWT: https://jwt.io/
* Refresh Tokens: https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/
* Spring security architecture: https://spring.io/guides/topicals/spring-security-architecture/
* Java Cryptography: http://tutorials.jenkov.com/java-cryptography/index.html
* Cryptographic Storage Cheat Sheet： https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet
* JSON Web Tokens (JWT) Demystified: https://hackernoon.com/json-web-tokens-jwt-demystified-f7e202249640
* Validate JWT tokens using JWKS in Java：https://medium.com/trabe/validate-jwt-tokens-using-jwks-in-java-214f7014b5cf
* Nimbus JOSE + JWT：https://connect2id.com/products/nimbus-jose-jwt
