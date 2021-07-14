package com.example.democustomauthserver;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import org.apache.tomcat.util.codec.binary.Base64;

public class TestRSAJWS {

  public static RSAPrivateKey readPrivateKey(File file) throws Exception {
    String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());
    String privateKeyPEM = key
      .replace("-----BEGIN PRIVATE KEY-----", "")
      .replaceAll(System.lineSeparator(), "")
      .replace("-----END PRIVATE KEY-----", "");
    byte[] encoded = Base64.decodeBase64(privateKeyPEM);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
    return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
  }

  public static RSAPublicKey readPublicKey(File file) throws Exception {
    String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());
    String publicKeyPEM = key
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replaceAll(System.lineSeparator(), "")
      .replace("-----END PUBLIC KEY-----", "");
    byte[] encoded = Base64.decodeBase64(publicKeyPEM);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
    return (RSAPublicKey) keyFactory.generatePublic(keySpec);
  }

  public static void main(String[] args) throws Exception {
//    RSAKey rsaJWK = new RSAKeyGenerator(2048)
//      .keyID("123")
//      .generate();
//    RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();
  File publicKeyFile = new File("C:\\nxp\\workspaces\\sso\\democustomauthserver\\src\\main\\resources\\oauth-pub.key");
  File privateKeyFile = new File("C:\\nxp\\workspaces\\sso\\democustomauthserver\\src\\main\\resources\\oauth-private.key");


// Create RSA-signer with the private key
    JWSSigner signer = new RSASSASigner(readPrivateKey(privateKeyFile));

// Prepare JWT with claims set
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
      .subject("alice")
      .issuer("https://c2id.com")
      .expirationTime(new Date(new Date().getTime() + 60 * 1000))
      .build();

    SignedJWT signedJWT = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
      claimsSet);

// Compute the RSA signature
    signedJWT.sign(signer);

// To serialize to compact form, produces something like
// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
    String s = signedJWT.serialize();
    System.out.println("#got the JWT:"+s);

// On the consumer side, parse the JWS and verify its RSA signature
    signedJWT = SignedJWT.parse(s);

    JWSVerifier verifier = new RSASSAVerifier(readPublicKey(publicKeyFile));
    System.out.println("JWS verification status:"+signedJWT.verify(verifier));
  }
}
