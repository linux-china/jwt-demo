package org.mvnsearch.security.jwtdemo;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.HexFormat;

public class Secp256k1PublicKeyParser {

  public static PublicKey parseSecp256k1CompressedPublicKey(byte[] compressedPublicKeyBytes) throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    // 1. Retrieve the Curve Parameters
    X9ECParameters x9ECParameters = SECNamedCurves.getByName("secp256k1");
    ECCurve curve = x9ECParameters.getCurve();

    // 2. Decode the Compressed Point
    ECPoint ecPoint = curve.decodePoint(compressedPublicKeyBytes);

    // 3. Construct the Public Key
    ECParameterSpec ecParameterSpec = new ECParameterSpec(
      x9ECParameters.getCurve(),
      x9ECParameters.getG(),
      x9ECParameters.getN(),
      x9ECParameters.getH()
    );

    ECPublicKeySpec pubSpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
    KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
    return keyFactory.generatePublic(pubSpec);
  }

  public static PrivateKey parseSecp256k1PrivateKey(byte[] privateKeyBytes) throws Exception {
    // Add Bouncy Castle as a security provider
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    // Get the ECParameterSpec for secp256k1
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

    // Convert the private key bytes to a BigInteger
    BigInteger privateKeyValue = new BigInteger(1, privateKeyBytes);

    // Create an ECPrivateKeySpec
    ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyValue, ecSpec);

    // Get a KeyFactory for EC
    KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");

    // Generate the PrivateKey object
    return keyFactory.generatePrivate(privateKeySpec);
  }


  public static void main(String[] args) throws Exception {
    String publicKeyHex = "02e8d78f0da7fc3b529d503edd933ed8cdc79dbe5fd5d9bd480f1e63a09905f3b3";
    String privateKeyHex = "c4e79fecc6bfeb1fe3bf4d783ddf330339c1d89c875fd6edde04d7f1b6d28678";
    parseSecp256k1CompressedPublicKey(HexFormat.of().parseHex(publicKeyHex));
    parseSecp256k1PrivateKey(HexFormat.of().parseHex(privateKeyHex));
  }
}
