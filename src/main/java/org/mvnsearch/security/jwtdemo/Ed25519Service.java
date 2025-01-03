package org.mvnsearch.security.jwtdemo;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Ed25519Service {

    public static EdECPrivateKey readPrivateKey(byte[] privateKey) throws Exception {
        var pkcs8EncodedKeySpec = new X509EncodedKeySpec(privateKey);
        KeyFactory kf = KeyFactory.getInstance("EdDSA");
        return (EdECPrivateKey) kf.generatePrivate(pkcs8EncodedKeySpec);
    }

    public static EdECPublicKey readPublicKey(byte[] publicKey) throws Exception {
        var pkcs8EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        return (EdECPublicKey) kf.generatePublic(pkcs8EncodedKeySpec);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        return kpg.generateKeyPair();
    }
}
