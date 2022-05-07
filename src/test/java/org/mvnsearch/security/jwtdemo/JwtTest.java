package org.mvnsearch.security.jwtdemo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * JWT test with cache support
 *
 * @author linux_china
 */
public class JwtTest {

    private static JWTVerifier jwtVerifier;
    private static Algorithm algorithmHS;
    private static LoadingCache<String, DecodedJWT> tokenStore;

    @BeforeAll
    public static void setUp() throws Exception {
        algorithmHS = Algorithm.HMAC256("access-secret");
        jwtVerifier = JWT.require(algorithmHS).withIssuer("mvnsearch").build();
        tokenStore = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .refreshAfterWrite(1, TimeUnit.MINUTES)
                .build(token -> jwtVerifier.verify(token));
    }


    @Test
    public void testGenerateToken() throws Exception {
        String token = JWT.create()
                .withSubject("access-key")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 15000))
                .withClaim("appName","function1")
                .withClaim("nonce",true)
                .sign(algorithmHS);
        System.out.println(token);
    }

    @Test
    public void testVerify() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImlzcyI6Im12bnNlYXJjaCIsImlhdCI6MTUxNjI1OTQ3MiwiYXV0aG9yaXRpZXMiOlsiU01TIl19.5-tYkDPzNItMG3Sq7iXjZHOIisCAflIP6IGKNreTo7A";
        DecodedJWT jwt = tokenStore.get(token);
        Claim claim = jwt.getClaim("authorities");
        String[] authorities = claim.asArray(String.class);
        assertNotNull(authorities);
        for (String authority : authorities) {
            System.out.println(authority);
        }
    }

}
