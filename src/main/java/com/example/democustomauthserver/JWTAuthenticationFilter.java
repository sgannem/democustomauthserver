package com.example.democustomauthserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.FileCopyUtils;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private AuthenticationManager authenticationManager;

  @Autowired
  private ResourceLoader resourceLoader;

  public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;

//    setFilterProcessesUrl("/api/services/controller/user/login");
    setFilterProcessesUrl("/signup");
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest req,
    HttpServletResponse res) throws AuthenticationException {
    try {
      User creds = new ObjectMapper()
        .readValue(req.getInputStream(), User.class);

      return authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
          creds.getUserName(),
          creds.getPassword(),
          new ArrayList<>())
      );
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest req,
    HttpServletResponse res,
    FilterChain chain,
    Authentication auth) throws IOException {

    // Reading private key.
    Resource resource = new ClassPathResource("classpath:/oauth-private.key");
    InputStream inputStream = resource.getInputStream();
    try {
      byte[] oauthPrivateKeyData = FileCopyUtils.copyToByteArray(inputStream);
      String data = new String(oauthPrivateKeyData, StandardCharsets.UTF_8);
      System.out.println(data);
      JWSSigner signer = new RSASSASigner(readPrivateKey(data));
      // Prepare JWT with claims set
      long issuedTime = System.currentTimeMillis();
      JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
        .subject(String.valueOf(auth.getPrincipal()))
        .issuer("mwallet2go")
        .issueTime(new Date(issuedTime))
        .expirationTime(new Date(issuedTime + SecurityConstants.EXPIRATION_TIME))
        .build();

      SignedJWT signedJWT = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
        claimsSet);

// Compute the RSA signature
      signedJWT.sign(signer);
      String token = signedJWT.serialize();
      System.out.println("#got the JWT:" + token);
      String body = auth.getPrincipal() + " " + token;
      res.getWriter().write(body);
      res.getWriter().flush();
    } catch (Exception e) {
      System.out.println("Exception:" + e);
    }
  }

  public RSAPrivateKey readPrivateKey(String data) throws Exception {
    String privateKeyPEM = data
      .replace("-----BEGIN PRIVATE KEY-----", "")
      .replaceAll(System.lineSeparator(), "")
      .replace("-----END PRIVATE KEY-----", "");
    byte[] encoded = Base64.decodeBase64(privateKeyPEM);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
    return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
  }
}
