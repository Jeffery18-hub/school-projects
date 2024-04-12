import java.io.*;
import java.net.*;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;

public class Server {
	public DHKeyPair serverDHKeys_;
	public Certificate serverCert_;
	public byte[] serverSignedDHPub_;
	public ServerSocket serverSock_;
	public ArrayList<byte[]> handshakeMsgs_;

	public Server(int port) throws IOException {
		serverDHKeys_ = CryptoUtils.initDHKeys();
		serverCert_ = CryptoUtils.getCert(CryptoUtils.base_path + "CASignedServerCertificate.pem");
		serverSignedDHPub_ = CryptoUtils.signDHPub(serverDHKeys_.getPublicKey(),
				CryptoUtils.getRSAPrivateKey(CryptoUtils.base_path + "serverPrivateKey.der"));
		serverSock_ = new ServerSocket(port);
		handshakeMsgs_ = new ArrayList<>();
	}

	public static void main(String[] args) throws IOException {
		Server server = new Server(6666);
		System.out.println("server is running...");
		for (;;) {
			Socket sock = server.serverSock_.accept();
			System.out.println("connected from " + sock.getRemoteSocketAddress());
			Thread t = new Handler(sock, server);
			t.start();
		}
	}
}

class Handler extends Thread {
	Socket sock_;
	Server server_;

	public Handler(Socket sock, Server server) {
		sock_ = sock;
		server_ = server;
	}

	@Override
	public void run() {
		try {
			// hint：init ObjectOutputStream brefore ObjectInputStream may contributue to blocking
			ObjectOutputStream output = new ObjectOutputStream(sock_.getOutputStream());
			output.flush(); // flush ObjectOutputStream before
			ObjectInputStream input = new ObjectInputStream(sock_.getInputStream());

			handle(input, output);

			input.close();
			output.close();
			sock_.close();
		} catch (Exception e) {
			try {
				sock_.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
			System.out.println("Client disconnected.");
		}
	}

	private void handle(ObjectInputStream input, ObjectOutputStream output)
			throws Exception {
		try {
			//send something before handshake for fun
			output.writeObject("hello before handshake");
			output.flush();

			byte[] nonce = (byte[]) input.readObject();
			server_.handshakeMsgs_.add(nonce); // add to msgs list
			System.out.println("nonce from client: " + CryptoUtils.bytesToHexStr(nonce));

			// send cert, signedDHPub, and DHPub to client
			output.writeObject(server_.serverCert_);
			output.flush();
			output.writeObject(server_.serverDHKeys_.getPublicKey());
			output.flush();
			output.writeObject(server_.serverSignedDHPub_);
			output.flush();
			server_.handshakeMsgs_.add(server_.serverCert_.getEncoded());
			server_.handshakeMsgs_.add(server_.serverDHKeys_.getPublicKey().getEncoded());
			server_.handshakeMsgs_.add(server_.serverSignedDHPub_);

			// read cert, dhpub and signed dhpub from client
			Certificate clientCert = (Certificate) input.readObject();
			PublicKey clientDHPub = (PublicKey) input.readObject();
			byte[] clientSignedDHPub = (byte[]) input.readObject();
			server_.handshakeMsgs_.add(clientCert.getEncoded());
			server_.handshakeMsgs_.add(clientDHPub.getEncoded());
			server_.handshakeMsgs_.add(clientSignedDHPub);

			boolean isClientCertValid = CryptoUtils
					.verifyCert(CryptoUtils.getCert(CryptoUtils.base_path + "CACertificate.pem"), clientCert);
			boolean isClientSignedDHPubValid = CryptoUtils.verifyDHPub(clientDHPub, clientCert.getPublicKey(),
					clientSignedDHPub);

			if (isClientSignedDHPubValid && isClientCertValid) {
				System.out.println("cert and signed dhpub are valid.");
			} else {
				// stop the program
				System.out.println("cert or signed dhpub are not valid.");
				System.exit(0);
			}

			// generate master key
			byte[] masterKey = CryptoUtils.generateMasterKey(clientDHPub, server_.serverDHKeys_.getPrivateKey());
			System.out.println("master key: " + CryptoUtils.bytesToHexStr(masterKey));

			// generate session keys
			HashMap<String, byte[]> sessionKeys = CryptoUtils.generateSecretKeys(nonce, masterKey);

			// send hmac
			byte[] hmacFromServer = CryptoUtils.generateHMAC(CryptoUtils.listToByteArray(server_.handshakeMsgs_),
					sessionKeys.get("serverMAC"));
			output.writeObject(hmacFromServer);
			output.flush();
			server_.handshakeMsgs_.add(hmacFromServer);
			// System.out.println("hmac: " + CryptoUtils.bytesToHexStr(hmac));

			// read hmac from client
			byte[] hmacFromClient = (byte[]) input.readObject();

			// verify hmac
			boolean isHmacValid = CryptoUtils.verifyHMAC(CryptoUtils.listToByteArray(server_.handshakeMsgs_), hmacFromClient,
					sessionKeys.get("clientMAC"));
			if (isHmacValid) {
				System.out.println("hmac is valid.");
			} else {
				// stop the program
				System.out.println("hmac is not valid.");
				System.exit(0);
			}

			// print finish handshake
			System.out.println("[server side]: finish handshake");

			while (true) {
				// read from client
				byte[] cipherFromClient = (byte[]) input.readObject();
				byte[] plainFromClient = CryptoUtils.decryptMessage(cipherFromClient, sessionKeys.get("clientEncrypt"),
						sessionKeys.get("clientIV"), sessionKeys.get("clientMAC"));
				String plainStrFromClient = CryptoUtils.bytesToString(plainFromClient);
				String plainStrFromServer = "OK from server: " + plainStrFromClient;
				byte[] cipherFromServer = CryptoUtils.encryptMessage(plainStrFromServer,
						sessionKeys.get("serverEncrypt"), sessionKeys.get("serverIV"),
						sessionKeys.get("serverMAC"));
		
				if ("bye".equals(plainStrFromClient)) {
					output.writeObject(cipherFromServer);
					output.flush();
					server_.handshakeMsgs_ = new ArrayList<>();
					System.out.println("server is disconnected with the client: " + sock_.getRemoteSocketAddress());
					break;
				}
				output.writeObject(cipherFromServer);
				output.flush();
			}

		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}
}