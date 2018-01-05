Spring Security with JWT
========================

JWT（JSON Web Tokens) is very useful for API gateway to authorize the user

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


### Attention

* anonymous for actuator and white urls list

# References

* JWT: https://jwt.io/
* Spring security architecture: https://spring.io/guides/topicals/spring-security-architecture/