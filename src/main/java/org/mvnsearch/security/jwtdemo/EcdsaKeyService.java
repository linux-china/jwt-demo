package org.mvnsearch.security.jwtdemo;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.stream.Collectors;

/**
 * ECDSA key service
 *
 * @author linux_china
 */
public class EcdsaKeyService {

    public static ECPrivateKey readPrivateKey(byte[] privateKey) throws Exception {
        AlgorithmParameters a = AlgorithmParameters.getInstance("EC");
        a.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec p = a.getParameterSpec(ECParameterSpec.class);
        BigInteger s = new BigInteger(1, privateKey);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPrivateKey) kf.generatePrivate(new ECPrivateKeySpec(s, p));
    }

    public static ECPrivateKey readPrivateKey(String pemText) throws Exception {
        byte[] privateKey = Base64.getDecoder().decode(extractBase64(pemText));
        return readPrivateKey(privateKey);
    }

    public static ECPublicKey readPublicKey(byte[] publicKey) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        return (ECPublicKey) kf.generatePublic(keySpec);
    }

    public static ECPublicKey readPublicKey(String pemText) throws Exception {
        byte[] publicKey = Base64.getDecoder().decode(extractBase64(pemText));
        return readPublicKey(publicKey);
    }

    public static String extractBase64(String pemText) {
        return pemText.lines()
                .filter(line -> !line.startsWith("--") && !line.isEmpty())
                .collect(Collectors.joining(""));
    }

}
