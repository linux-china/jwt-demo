package org.mvnsearch.security.jwtdemo;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

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
    public void testExtractPem() throws Exception {
        String text = "-----BEGIN PRIVATE KEY-----\n" +
                "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBMQppuNBg3V/u7UlrB\n" +
                "UiynuWnr0sxO/elVi3agVRjcmQ==\n" +
                "-----END PRIVATE KEY-----";
        String pubKeyText = EcdsaKeyService.extractBase64(text);
        byte[] bytes = Base64.getDecoder().decode(pubKeyText);
        EcdsaKeyService.readPrivateKey(bytes);
    }
}
