package org.mvnsearch.security.jwtdemo;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import java.util.Date;


public class Secp256k1Test {

  @BeforeAll
  public static void setUp() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void testKeyGeneration() throws Exception {
    // Generate secp256k1 key pair
    KeyPair keyPair = generateSecp256k1KeyPair();

    // Extract private and public keys
    ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
    // Create a JWT and sign it with the private key
    String jwt = createJwt(privateKey);
    System.out.println("Generated JWT: " + jwt);

    // Verify the JWT using the public key
    boolean isValid = verifyJwt(jwt, publicKey);
    System.out.println("Is JWT valid? " + isValid);
  }


  @Test
  public void testJwt() throws Exception {
    // Generate EC key pair on the secp256k1 curve
    ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1)
      .keyUse(KeyUse.SIGNATURE)
      .provider(BouncyCastleProviderSingleton.getInstance())
      .generate();

    // Get the public EC key, for recipients to validate the signatures
    ECDSASigner signer = new ECDSASigner(ecJWK);
    signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance()); // add


    // Sample JWT claims
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
      .subject("alice")
      .build();

    // Create JWT for ES256K alg
    SignedJWT jwt = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.ES256K)
        .build(),
      claimsSet);

    // Sign with private EC key
    jwt.sign(signer);

    // Output the JWT
    System.out.println(jwt.serialize());

  }

  private static KeyPair generateSecp256k1KeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
    keyPairGenerator.initialize(ecSpec, new SecureRandom());
    return keyPairGenerator.generateKeyPair();
  }

  private static String createJwt(ECPrivateKey privateKey) throws JOSEException {
    // Create the JWT claims
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
      .subject("example-user")
      .issuer("example-issuer")
      .issueTime(new Date())
      .expirationTime(new Date(System.currentTimeMillis() + 3600000)) // 1 hour expiration
      .build();

    // Create the JWS header with ES256K algorithm
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256K)
      .type(JOSEObjectType.JWT)
      .build();

    // Create the signed JWT
    SignedJWT signedJWT = new SignedJWT(header, claimsSet);

    // Sign the JWT with the private key
    JWSSigner signer = new ECDSASigner(privateKey);
    signedJWT.sign(signer);

    // Serialize the JWT to a compact string
    return signedJWT.serialize();
  }

  private static boolean verifyJwt(String jwt, ECPublicKey publicKey) throws JOSEException, ParseException {
    // Parse the signed JWT
    SignedJWT signedJWT = SignedJWT.parse(jwt);

    // Create a verifier with the public key
    JWSVerifier verifier = new ECDSAVerifier(publicKey);

    // Verify the signature
    return signedJWT.verify(verifier);
  }
}
