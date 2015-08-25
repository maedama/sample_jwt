package com.maedama.sample_jwt;

import java.io.File;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.UUID;

import org.apache.commons.io.FileUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Hello world!
 *
 */
public class App {
	public static void main(String[] args) {
		
		JWSSignerFactory factory = new JWSSignerFactory();
		JWSSigner signer = factory.build("etc/private_key.pk8");
		
		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setCustomClaim("typ", "id_token");
		claimsSet.setJWTID(UUID.randomUUID().toString());
		claimsSet.setSubject("100");
		claimsSet.setIssuer("https://maedama.com");
		
		claimsSet.setExpirationTime(new Date(new Date().getTime() + 600 * 1000L)); // 10min from now		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256),
				claimsSet);

		try {
			signedJWT.sign(signer);
		} catch (JOSEException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(signedJWT.serialize());
		
	}

	private static class JWSSignerFactory {

		public static JWSSigner build(String privateKeyPath) {

			JWSSigner result = null;

			File privateKeyFile = new File(privateKeyPath);
			byte[] privateKeyBytes;

			try {
				privateKeyBytes = FileUtils.readFileToByteArray(privateKeyFile);

				KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or
																// whatever
				PrivateKey privateKey = kf
						.generatePrivate(new PKCS8EncodedKeySpec(
								privateKeyBytes));
				result = new RSASSASigner((RSAPrivateKey) privateKey);
			} catch (Exception e) {
			}
			return result;
		}
	}

}
