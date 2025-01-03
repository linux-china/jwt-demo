package org.mvnsearch.security.jwtdemo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * jwt with Ed25519
 */
public class JwtEdDSATest {

    @Test
    public void testJwtVerify() throws Exception {
        OctetKeyPair jwk = loadPairs(new File("src/main/resources/ed25519/key-pairs.json")); // generatePairs();
        OctetKeyPair publicJWK = jwk.toPublicJWK();
        // Create the EdDSA signer
        JWSSigner signer = new Ed25519Signer(jwk);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("https://c2id.com")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(jwk.getKeyID()).build(),
                claimsSet);

        // Compute the EC signature
        signedJWT.sign(signer);

        // Serialize the JWS to compact form
        String token = signedJWT.serialize();

        // On the consumer side, parse the JWS and verify its EdDSA signature
        signedJWT = SignedJWT.parse(token);

        JWSVerifier verifier = new Ed25519Verifier(publicJWK);
        assertTrue(signedJWT.verify(verifier));

        // Retrieve / verify the JWT claims according to the app requirements
        assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("https://c2id.com", signedJWT.getJWTClaimsSet().getIssuer());
        assertTrue(new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime()));

    }

    @Test
    public void testBase64() {
        byte[] bytes = Base64.getUrlDecoder().decode("gQTln1ZTj-8jJ1PnBRWnsBTJgZ-84umDOpdz7s8D8Ms");
        System.out.println(bytes.length);
    }

    public OctetKeyPair generatePairs() throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("123")
                .generate();
    }

    public OctetKeyPair loadPairs(File jwkFile) throws Exception {
        JWKSet jwkSet = JWKSet.load(jwkFile);
        JWK jwk = jwkSet.getKeys().get(0);
        return jwk.toOctetKeyPair();
    }
}
