package org.mvnsearch.security.jwtdemo;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

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

    public static ECPublicKey readPublicKey(byte[] publicKey) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        return (ECPublicKey) kf.generatePublic(keySpec);
    }

    public static ECParameterSpec ecParameterSpecForCurve(String curveName) throws NoSuchAlgorithmException, InvalidParameterSpecException {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curveName));
        return params.getParameterSpec(ECParameterSpec.class);
    }

}
