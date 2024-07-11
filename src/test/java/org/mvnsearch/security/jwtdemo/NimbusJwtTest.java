package org.mvnsearch.security.jwtdemo;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import java.security.interfaces.ECPublicKey;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

public class NimbusJwtTest {

    @Test
    public void testJwks() throws Exception {
        ECKey jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                .issueTime(new Date()) // issued-at timestamp (optional)
                .generate();
        // Output the private and public EC JWK parameters
        System.out.println(jwk);
        // Output the public EC JWK parameters only
        System.out.println(jwk.toPublicJWK());
    }

    @Test
    public void testGeneratePublicJwks() throws Exception {
        byte[] publicKeyBytes = IOUtils.toByteArray(EcdsaKeyServiceTest.class.getResourceAsStream("/ecdsa_keys/public_key.der"));
        ECPublicKey pubKey = EcdsaKeyService.readPublicKey(publicKeyBytes);
        ECKey ecKey = new ECKey.Builder(Curve.P_256, pubKey)
                .algorithm(Algorithm.parse("ES256"))
                .keyID("86837c15-9f38-4599-a301-77a2c43c16d1")
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(Set.of(KeyOperation.VERIFY))
                .build();
        System.out.println(ecKey.toPublicJWK());
    }
}
