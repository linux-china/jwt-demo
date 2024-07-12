package org.mvnsearch.security.jwtdemo;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

public class EcdsaKeyServiceTest {

    @SuppressWarnings("DataFlowIssue")
    @Test
    public void testReadKeys() throws Exception {
        byte[] privateKey = IOUtils.toByteArray(EcdsaKeyServiceTest.class.getResourceAsStream("/ecdsa_keys/private_key.der"));
        byte[] publicKey = IOUtils.toByteArray(EcdsaKeyServiceTest.class.getResourceAsStream("/ecdsa_keys/public_key.der"));
        EcdsaKeyService.readPrivateKey(privateKey);
        EcdsaKeyService.readPublicKey(publicKey);
    }

    @Test
    public void testGenerateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        // secp256r1 == NIST P-256
        ECGenParameterSpec m = new ECGenParameterSpec("secp256r1");
        kpg.initialize(m);
        KeyPair keyPair = kpg.generateKeyPair();
        // write der format
        IOUtils.write(keyPair.getPrivate().getEncoded(), new FileOutputStream("src/main/resources/ecdsa_keys/private_key.der"));
        IOUtils.write(keyPair.getPublic().getEncoded(), new FileOutputStream("src/main/resources/ecdsa_keys/public_key.der"));
        // writer pem format
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                DatatypeConverter.printBase64Binary(keyPair.getPrivate().getEncoded()) +
                "\n-----END PRIVATE KEY-----\n";
        String pubKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                DatatypeConverter.printBase64Binary(keyPair.getPrivate().getEncoded()) +
                "\n-----END PUBLIC KEY-----\n";
        IOUtils.write(privateKeyPem, new FileOutputStream("src/main/resources/ecdsa_keys/ec-p256-priv-key.pem"), StandardCharsets.UTF_8);
        IOUtils.write(pubKeyPem, new FileOutputStream("src/main/resources/ecdsa_keys/ec-p256-pub-key.pem"), StandardCharsets.UTF_8);

    }

    @Test
    public void testExtractPem() {
        String text = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJpjgxRYJ8m2QxspbJ7r\n" +
                "k26Ck6ONuUK8Kuwv6/0GKhuVUCbOsVkgF8jaNMJpVZTbDp+1TPholLHD93vrfZTe\n" +
                "7G/ndPsWSf9vXlHsJwRdE4Mv40aPQr2cmlUO1Ws+asUhNf7EV+1kZ2JFbUGlQPcO\n" +
                "pb01nS6baslY7Yn9NNxg1RSVgYNypdVdtlVxgUpxmR9ME18XrB/WUIDvqxO67ocu\n" +
                "afT/3fU0jPRs7i+v7RJMyUQALNe5XsqoqQZAekURjBtrlzHwzfUQo2aNb5g9vZle\n" +
                "ZF8ogftcy/27qIzTuV83fp55CJh3B/mPMO/zfr/gDRctoUCchKvxxQ2GaN7pZwPn\n" +
                "hQIDAQAB\n" +
                "-----END PUBLIC KEY-----";
        System.out.println(EcdsaKeyService.extractBase64(text));
    }
}
