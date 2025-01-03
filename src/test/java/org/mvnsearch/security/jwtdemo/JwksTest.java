package org.mvnsearch.security.jwtdemo;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;

public class JwksTest {

    @Test
    public void testRetrieveJwks() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4eXh5IiwiaXNzIjoibXZuc2VhcmNoIiwiaWF0IjoxNTE2MjU4ODMxLCJhdXRob3JpdGllcyI6WyJTTVMiXX0.eKTXsQsnKA3l6Hy-5dmf7CFL7zntfmbrkDIG3dnc6FrTtLO3BrvPpj2d2X_ULDVUU9k5n3rIXfKVlD3qHtgtytYF6Sn5MpqbHUYRttDb4NQnM5MUJKY8LNfCk05gJ5xMYJLa9Vk52oe7h42TT2O01KrSX-rLjJaUxbCL3Cz4XQlmbc5o-1hIoc7G-QgSPT6b-zXDWROFSBl0J6eIsifQbL2FaM2SeOKoiwpBQQW3-YOFShMK58Ns7mDj0lAiOqq1yCoFbigAyeSM-y32tye68aJmaWZB_1KxO-h4PTfR9JHVu1BbWcxgPudGPM071fWQB1TB5rPDfVrd8eYuT0rOCg";
        DecodedJWT jwt = JWT.decode(token);
        URL url = this.getClass().getResource("/rsa_keys/jwks.json");
        JwkProvider jwkProvider = new UrlJwkProvider(url);
        Jwk jwk = jwkProvider.get("6e8b1b55-0c3c-424f-b4cc-14f9126c1c2c");
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
        algorithm.verify(jwt);
        System.out.println(new ObjectMapper().writeValueAsString(jwk));
    }

    @Test
    public void testValidateJwk() throws Exception {
        String domain = "http://localhost:8080";
        UrlJwkProvider jwkProvider = new UrlJwkProvider(domain);
        Jwk jwk = jwkProvider.get("JWT-RS256-Midea-pub");
        System.out.println(jwk.getPublicKey().getAlgorithm());
    }
}
