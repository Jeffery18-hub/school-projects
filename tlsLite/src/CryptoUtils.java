import java.util.Arrays;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

@SuppressWarnings("unused")
public class CryptoUtils {
	final static String base_path = "tlsLite_config/";

	/*
	 * the client will pick a random *nonce* for each connection(in addition to its
	 * Diffie-Hellman private key).
	 * The *nonce* can be 32 bytes from a `SecureRandom` object.
	 */

	public static byte[] generateNonce() {
		byte[] nonce = new byte[32];
		new SecureRandom().nextBytes(nonce);
		return nonce;
	}

	// Convert byte array to hex string
	public static String bytesToHexStr(byte[] bytes) {
		StringBuilder hexString = new StringBuilder();
		for (byte b : bytes) {
			String hex = Integer.toHexString(0xff & b); // convert to unsigned
			if (hex.length() == 1) { // add leading zero
				hexString.append('0');
			}
			hexString.append(hex);
		}
		return hexString.toString();
	}

	/*
	 * The server and client will also agree on Diffie-Hellman parameters *g* and
	 * *N*.
	 * keys can be derieved: serverDHPub = g^serverDHPriv mod N
	 * and clientDHPub = g^clientDHPriv mod N.
	 */

	public static DHKeyPair initDHKeys() {
		String hexN = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE653DCC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
		BigInteger N = new BigInteger(hexN, 16);
		BigInteger g = BigInteger.valueOf(2);
		BigInteger dhPriv = generateDHPriv();
		BigInteger dhPub = generateDHPub(dhPriv, g, N);

		try {
			// convert big integer to private key
			KeyFactory keyFactory = KeyFactory.getInstance("DH");
			DHPrivateKeySpec privKeySpec = new DHPrivateKeySpec(dhPriv, N, g);
			PrivateKey dhPrivKey = keyFactory.generatePrivate(privKeySpec);

			// convert big integer to public key
			DHPublicKeySpec pubKeySpec = new DHPublicKeySpec(dhPub, N, g);
			PublicKey dhPubKey = keyFactory.generatePublic(pubKeySpec);
			return new DHKeyPair(dhPubKey, dhPrivKey);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public static PrivateKey getRSAPrivateKey(String keyPath) {
		try {

			// read .der
			byte[] privateKeyBytes = Files.readAllBytes(Paths.get(keyPath));

			// PKCS8EncodedKeySpec object
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);

			// KeyFactory object with RSA algorithm
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(spec);

			return privateKey;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static BigInteger generateDHPriv() {
		SecureRandom random = new SecureRandom();
		BigInteger priv = new BigInteger(2048, random);
		return priv;
	}

	public static BigInteger generateDHPub(BigInteger DHPriv, BigInteger g, BigInteger N) {
		BigInteger pub = g.modPow(DHPriv, N);
		return pub;
	}

	// sign the dh public key with RAS private key
	public static byte[] signDHPub(PublicKey DHPub, PrivateKey RASPriv) {
		try {
			Signature sig = Signature.getInstance("SHA256withRSA");
			sig.initSign(RASPriv);
			sig.update(DHPub.getEncoded());

			byte[] signature = sig.sign(); // sign the hash code
			return signature;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	// verify the signature
	public static boolean verifyDHPub(PublicKey DHPub, PublicKey RASPub, byte[] signature) {
		try {
			Signature sig = Signature.getInstance("SHA256withRSA");
			sig.initVerify(RASPub);
			sig.update(DHPub.getEncoded());
			return sig.verify(signature);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	// public static boolean verifyCert(Certificate CACert, Certificate targetCert)
	// {
	// try {
	// CertificateFactory certificateFactory =
	// CertificateFactory.getInstance("X.509");
	// // trust anchor
	// TrustAnchor trustAnchor = new TrustAnchor((X509Certificate)CACert, null);

	// // cert chain
	// List<Certificate> certs = new ArrayList<>();
	// certs.add(targetCert);
	// CertPath certPath = certificateFactory.generateCertPath(certs);

	// // set up PKIX parameters
	// PKIXParameters params = new
	// PKIXParameters(Collections.singleton(trustAnchor));
	// params.setRevocationEnabled(false);

	// // validate cert chain
	// CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
	// certPathValidator.validate(certPath, params);
	// // cert is valid(no exception)
	// return true;
	// } catch (CertificateException | InvalidAlgorithmParameterException |
	// NoSuchAlgorithmException | CertPathValidatorException e) {
	// // Log the exception
	// System.out.println("Certificate validation failed: " + e.getMessage());
	// return false;
	// }
	// }

	public static boolean verifyCert(Certificate CACert, Certificate targetCert) {
		PublicKey CApubKey = CACert.getPublicKey();
		try {
			targetCert.verify(CApubKey); // use CA public key to verify
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public static byte[] generateMasterKey(PublicKey otherDHPub, PrivateKey myDHPriv) {
		try {
			KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
			keyAgreement.init(myDHPriv);
			keyAgreement.doPhase(otherDHPub, true);

			// master key
			byte[] sharedSecret = keyAgreement.generateSecret();

			return sharedSecret;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	// function hdkfExpand(input, tag): // tag is a string, but that's easily
	// converted to byte[]
	// okm = HMAC(key = input, data = tag concatenated with a byte with value 1)
	// return first 16 bytes of okm

	private static byte[] hdkfExpand(byte[] inputKey, String tagStr) {
		try {// converted to byte[]
			byte[] tagBytes = (tagStr + "\u0001").getBytes(StandardCharsets.UTF_8);

			// HMAC-SHA256 instance
			Mac mac = Mac.getInstance("HmacSHA256");
			SecretKeySpec keySpec = new SecretKeySpec(inputKey, "HmacSHA256");
			mac.init(keySpec);

			// use HMAC-SHA256 to compute（OKM）
			byte[] okm = mac.doFinal(tagBytes);

			return Arrays.copyOf(okm, 16);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static HashMap<String, byte[]> generateSecretKeys(byte[] clientNonce, byte[] sharedSecretFromDiffieHellman) {
		// HMAC-SHA256 instance
		// use HMAC-SHA256 to compute（OKM）
		byte[] prk = null;
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			SecretKeySpec keySpec = new SecretKeySpec(clientNonce, "HmacSHA256");
			mac.init(keySpec);
			prk = mac.doFinal(sharedSecretFromDiffieHellman);
		} catch (Exception e) {
			e.printStackTrace();
		}
		byte[] serverEncrypt = hdkfExpand(prk, "server encrypt");
		byte[] clientEncrypt = hdkfExpand(serverEncrypt, "client encrypt");
		byte[] serverMAC = hdkfExpand(clientEncrypt, "server MAC");
		byte[] clientMAC = hdkfExpand(serverMAC, "client MAC");
		byte[] serverIV = hdkfExpand(clientMAC, "server IV");
		byte[] clientIV = hdkfExpand(serverIV, "client IV");

		HashMap<String, byte[]> secretKeys = new HashMap<>();
		secretKeys.put("serverEncrypt", serverEncrypt);
		secretKeys.put("clientEncrypt", clientEncrypt);
		secretKeys.put("serverMAC", serverMAC);
		secretKeys.put("clientMAC", clientMAC);
		secretKeys.put("serverIV", serverIV);
		secretKeys.put("clientIV", clientIV);

		return secretKeys;
	}

	// test purpose
	public static byte[] generateHMAC(String message, byte[] MACKey) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			SecretKeySpec secretKeySpec = new SecretKeySpec(MACKey, "HmacSHA256");
			mac.init(secretKeySpec);
			return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] generateHMAC(byte[] message, byte[] MACKey) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			SecretKeySpec secretKeySpec = new SecretKeySpec(MACKey, "HmacSHA256");
			mac.init(secretKeySpec);
			return mac.doFinal(message);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static boolean verifyHMAC(String message, byte[] HMAC, byte[] MACKey) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			SecretKeySpec secretKeySpec = new SecretKeySpec(MACKey, "HmacSHA256");
			mac.init(secretKeySpec);
			return MessageDigest.isEqual(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)), HMAC);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	public static boolean verifyHMAC(byte[] message, byte[] HMAC, byte[] MACKey) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			SecretKeySpec secretKeySpec = new SecretKeySpec(MACKey, "HmacSHA256");
			mac.init(secretKeySpec);
			return MessageDigest.isEqual(mac.doFinal(message), HMAC);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	public static Certificate getCert(String certPath) {
		// create CertificateFactory instance
		try {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			// read file
			FileInputStream inputStream = new FileInputStream(certPath);
			Certificate cert = certificateFactory.generateCertificate(inputStream);
			inputStream.close();
			return cert;
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}


	public static byte[] encryptMessage(String message, byte[] encryptionKey, byte[] iv, byte[] macKey) throws Exception {
		// Compute HMAC
		byte[] hmac = generateHMAC(message, macKey);

		// Concatenate message and HMAC
		byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
		byte[] messagePlusHmac = new byte[messageBytes.length + hmac.length];
		System.arraycopy(messageBytes, 0, messagePlusHmac, 0, messageBytes.length);
		System.arraycopy(hmac, 0, messagePlusHmac, messageBytes.length, hmac.length);

		// Encrypt using AES/CBC/PKCS5Padding
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

		return cipher.doFinal(messagePlusHmac);
	}

	public static byte[] encryptMessage(byte[] messageBytes, byte[] encryptionKey, byte[] iv, byte[] macKey)
			throws Exception {
		// Compute HMAC
		byte[] hmac = generateHMAC(messageBytes, macKey);

		// Concatenate message and HMAC
		byte[] messagePlusHmac = new byte[messageBytes.length + hmac.length];
		System.arraycopy(messageBytes, 0, messagePlusHmac, 0, messageBytes.length);
		System.arraycopy(hmac, 0, messagePlusHmac, messageBytes.length, hmac.length);

		// Encrypt using AES/CBC/PKCS5Padding
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

		return cipher.doFinal(messagePlusHmac);
	}

	public static byte[] decryptMessage(byte[] cipherBytes, byte[] encryptionKey, byte[] iv, byte[] macKey)
			throws Exception {
		// Decrypt using AES/CBC/PKCS5Padding
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

		// Extract message and HMAC
		byte[] messagePlusHmac = cipher.doFinal(cipherBytes);
		byte[] plainMsg = Arrays.copyOfRange(messagePlusHmac, 0, messagePlusHmac.length - 32);
		byte[] hmac = Arrays.copyOfRange(messagePlusHmac, messagePlusHmac.length - 32, messagePlusHmac.length);

		// Verify HMAC
		if (!verifyHMAC(plainMsg, hmac, macKey)) {
			throw new Exception("HMAC verification failed");
		}

		return plainMsg;
	}

	public static String bytesToString(byte[] bytes) {
		return new String(bytes, StandardCharsets.UTF_8);
	}

	public static byte[] listToByteArray(List<byte[]> list) {
		int totalLength = list.stream().mapToInt(a -> a.length).sum();

		// new byte[] with totalLength
		byte[] combined = new byte[totalLength];

		int currentPosition = 0;
		for (byte[] array : list) {
			System.arraycopy(array, 0, combined, currentPosition, array.length);
			currentPosition += array.length;
		}
		return combined;
	}

}

class DHKeyPair {
	private PublicKey publicKey;
	private PrivateKey privateKey;

	public DHKeyPair(PublicKey publicKey, PrivateKey privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}
}