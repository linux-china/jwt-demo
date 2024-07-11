package org.mvnsearch.security.jwtdemo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Date;

/**
 * JWT ECDSA test
 *
 * @author linux_china
 */
public class JwtEcdsaTest {
    private static JWTVerifier jwtVerifier;
    private static Algorithm algorithmEcdsa256Private;
    private static Algorithm algorithmEcdsa256Public;

    @BeforeAll
    public static void setUp() throws Exception {
        byte[] privateKeyBytes = IOUtils.toByteArray(EcdsaKeyServiceTest.class.getResourceAsStream("/ecdsa_keys/private_key.der"));
        byte[] publicKeyBytes = IOUtils.toByteArray(EcdsaKeyServiceTest.class.getResourceAsStream("/ecdsa_keys/public_key.der"));
        ECPrivateKey privateKey = EcdsaKeyService.readPrivateKey(privateKeyBytes);
        ECPublicKey publicKey = EcdsaKeyService.readPublicKey(publicKeyBytes);
        algorithmEcdsa256Private = Algorithm.ECDSA256(null, privateKey);
        algorithmEcdsa256Public = Algorithm.ECDSA256(publicKey, privateKey);
        jwtVerifier = JWT.require(algorithmEcdsa256Public).withIssuer("mvnsearch").build();
    }

    @Test
    public void testGenerateToken() throws Exception {
        String token = JWT.create()
                .withIssuer("mvnsearch")
                .withSubject("xyxy")
                .withIssuedAt(new Date())
                .withArrayClaim("authorities", new String[]{"SMS"})
                .sign(algorithmEcdsa256Private);
        System.out.println(token);
        DecodedJWT jwt = jwtVerifier.verify(token);
        Claim claim = jwt.getClaim("authorities");
        String[] authorities = claim.asArray(String.class);
        for (String authority : authorities) {
            System.out.println(authority);
        }
    }

    @Test
    public void testVerify() throws Exception {
        String token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtdm5zZWFyY2giLCJzdWIiOiJ4eXh5IiwiaWF0IjoxNzIwNzA5OTE0LCJhdXRob3JpdGllcyI6WyJTTVMiXX0.nJK0CvG46wdwdMaW91WXceLbV4dGR2LqVJqUc54jHX0FfbbW5Zgxvm23CjSnaExfhYgQM0twl79PAyTsZOBpew";
        DecodedJWT jwt = jwtVerifier.verify(token);
        Claim claim = jwt.getClaim("authorities");
        String[] authorities = claim.asArray(String.class);
        for (String authority : authorities) {
            System.out.println(authority);
        }
    }

}
