import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PublicKey;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;


public class Client {
	private byte[] clientNonce_;
	private DHKeyPair clientDHKeys_;
	private Certificate clientCert_;
	private byte[] clientSignedDHPub_;
	private Socket sock_;
	private ArrayList<byte[]> handshakeMsgs_;
	

	public Client(String ip, int port) throws UnknownHostException, IOException {
		clientNonce_ = CryptoUtils.generateNonce();
		clientDHKeys_ = CryptoUtils.initDHKeys();
		clientCert_ = CryptoUtils.getCert(CryptoUtils.base_path + "CASignedClientCertificate.pem");
		clientSignedDHPub_ = CryptoUtils.signDHPub(clientDHKeys_.getPublicKey(), CryptoUtils.getRSAPrivateKey(CryptoUtils.base_path + "clientPrivateKey.der"));
		sock_ = new Socket(ip, port);
		handshakeMsgs_ = new ArrayList<>();
	}

	public static void main(String[] args) throws Exception {
		Client client = new Client("localhost", 6666);
		try (ObjectOutputStream out = new ObjectOutputStream(client.sock_.getOutputStream());
				ObjectInputStream in = new ObjectInputStream(client.sock_.getInputStream())) {
				client.handle(in, out);
		}
		client.sock_.close();
		System.out.println("disconnected.");
	}

	private void handle(ObjectInputStream in, ObjectOutputStream out) throws Exception {
		String message = (String) in.readObject();
		System.out.println("[server] " + message);
		
		// send nonce
		out.writeObject(clientNonce_);
		out.flush();
		handshakeMsgs_.add(clientNonce_); // add to msgs list

		// read cert, dhpub and signed dhpub from server
		Certificate serverCert = (Certificate) in.readObject();
		PublicKey serverDHPub = (PublicKey) in.readObject();
		byte[] serverSignedDHPub = (byte[]) in.readObject();
		handshakeMsgs_.add(serverCert.getEncoded());
		handshakeMsgs_.add(serverDHPub.getEncoded());
		handshakeMsgs_.add(serverSignedDHPub);

		// System.out.println("[server] cert: " + serverCert);
		// System.out.println("[server] dhpub: " + serverDHPub);
		// System.out.println("[server] signed dhpub: " + CryptoUtils.bytesToHexStr(serverSignedDHPub));


		boolean isServerCertValid = CryptoUtils.verifyCert(CryptoUtils.getCert(CryptoUtils.base_path + "CACertificate.pem"), serverCert);
		boolean isServerSignedDHPubValid = CryptoUtils.verifyDHPub(serverDHPub, serverCert.getPublicKey(), serverSignedDHPub);
		
		if (isServerSignedDHPubValid && isServerCertValid) {
			System.out.println("[server] cert and signed dhpub are valid.");
		}else {
			// stop the program
			System.out.println("[server] cert or signed dhpub are not valid.");
			System.exit(0);
		}

		// send cert, signedDHPub, and DHPub to server
		out.writeObject(clientCert_);
		out.writeObject(clientDHKeys_.getPublicKey());
		out.writeObject(clientSignedDHPub_);
		out.flush();
		handshakeMsgs_.add(clientCert_.getEncoded());
		handshakeMsgs_.add(clientDHKeys_.getPublicKey().getEncoded());
		handshakeMsgs_.add(clientSignedDHPub_);

		// generate master key
		byte[] masterKey = CryptoUtils.generateMasterKey(serverDHPub, clientDHKeys_.getPrivateKey());
		System.out.println("[master key] " + CryptoUtils.bytesToHexStr(masterKey));

		// generate session keys
		HashMap<String, byte[]> sessionKeys = CryptoUtils.generateSecretKeys(clientNonce_, masterKey);

		// read hmac from server
		byte[] hmacFromServer = (byte[]) in.readObject();
		// System.out.println("[server] hmac: " + CryptoUtils.bytesToHexStr(hmac));

		// verify hmac
		if (!CryptoUtils.verifyHMAC(CryptoUtils.listToByteArray(handshakeMsgs_), hmacFromServer, sessionKeys.get("serverMAC"))) {
			System.out.println("[server] hmac is not valid.");
			System.exit(0);
		}else {
			System.out.println("[server] hmac is valid.");
		}

		// add hmac to msgs list
		handshakeMsgs_.add(hmacFromServer);

		// send hmac to server(last step of handshake)
		// generate hmac first
		byte[] hmacFromClient = CryptoUtils.generateHMAC(CryptoUtils.listToByteArray(handshakeMsgs_), sessionKeys.get("clientMAC"));
		out.writeObject(hmacFromClient);
		out.flush();

		// print the handshake finish on console
		System.out.println("[client side] finish handshake");

		Scanner scanner = new Scanner(System.in);
		while (true) {
			System.out.print(">>> ");
			String s = scanner.nextLine();
			byte[] cipherFromClient = CryptoUtils.encryptMessage(s, sessionKeys.get("clientEncrypt"), 
				sessionKeys.get("clientIV"), sessionKeys.get("clientMAC"));
			out.writeObject(cipherFromClient); // send cipher to server
			out.flush();

			byte[] cipherFromServer = (byte[]) in.readObject(); // read response from server
			String cipherStrFromServer = CryptoUtils.bytesToString(cipherFromServer);
			byte[] plainFromServer = CryptoUtils.decryptMessage(cipherFromServer, sessionKeys.get("serverEncrypt"),
				sessionKeys.get("serverIV"), sessionKeys.get("serverMAC")); 
			String plainStrFromServer = CryptoUtils.bytesToString(plainFromServer);
			System.out.println("<<< - cipher " + cipherStrFromServer);
			System.out.println("<<< - plain " + plainStrFromServer);

			if ("OK from server: bye".equals(plainStrFromServer)) {
				scanner.close();
				break;
			}
		}
	}

}
