import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.HashMap;

class Test {
  @SuppressWarnings("unused")
  public static void main(String[] args) {
    
    // dh keys
    DHKeyPair clientDHKeys = CryptoUtils.initDHKeys();
    PublicKey clientDHPubKey = clientDHKeys.getPublicKey();
    PrivateKey clientDHPrivKey = clientDHKeys.getPrivateKey();

    DHKeyPair serverDHKeys = CryptoUtils.initDHKeys();
    PublicKey serverDHPubKey = serverDHKeys.getPublicKey();
    PrivateKey serverDHPrivKey = serverDHKeys.getPrivateKey();

    // client nonce
    byte[] clientNonce = CryptoUtils.generateNonce();
    String clientNonceHex = CryptoUtils.bytesToHexStr(clientNonce);

    // private rsa keys
    PrivateKey serverRSAPrivateKey = CryptoUtils.
      getRSAPrivateKey(CryptoUtils.base_path + "serverPrivateKey.der");

    PrivateKey clientRSAPrivateKey = CryptoUtils.
      getRSAPrivateKey(CryptoUtils.base_path + "clientPrivateKey.der");

    // sign the dh public key with RAS private key
    byte[] clientSignedDHpub = CryptoUtils.signDHPub(clientDHPubKey, clientRSAPrivateKey);
    byte[] serverSignedDHpub = CryptoUtils.signDHPub(serverDHPubKey, serverRSAPrivateKey);

    // get certs
    Certificate CACert = CryptoUtils.getCert(CryptoUtils.base_path + "CACertificate.pem");
    Certificate clientCert = CryptoUtils.getCert(CryptoUtils.base_path + "CASignedClientCertificate.pem");
    Certificate serverCert = CryptoUtils.getCert(CryptoUtils.base_path + "CASignedServerCertificate.pem");

    // get ras public keys from certs
    PublicKey caRASPubKey = CACert.getPublicKey();
    PublicKey serverRASPubKey = serverCert.getPublicKey();
    PublicKey clientRSAPubKey = clientCert.getPublicKey();

    // System.out.println("caRASPubKey: " + caRASPubKey);
    // System.out.println("serverRASPubKey: " + serverRASPubKey);
    // System.out.println("clientRSAPubKey: " + clientRSAPubKey);

    // verify the dh public key signatures with server and client ras public keys
    boolean isServerDHvalid = CryptoUtils.verifyDHPub(serverDHPubKey, serverRASPubKey, serverSignedDHpub);
    boolean isClientDHvalid = CryptoUtils.verifyDHPub(clientDHPubKey, clientRSAPubKey, clientSignedDHpub);

    // verify the server certificate on the client side
    boolean isServerCertValid = CryptoUtils.verifyCert(CACert, serverCert);

    // verify the client certificate on the server side
    boolean isClientCertValid = CryptoUtils.verifyCert(CACert, clientCert);

    // generate master keys
    byte[] serverMasterKey = CryptoUtils.generateMasterKey(clientDHPubKey, serverDHPrivKey);
    byte[] clientMasterKey = CryptoUtils.generateMasterKey(serverDHPubKey, clientDHPrivKey);
    byte[] dhMasterKey = serverMasterKey;

    // make secret keys
    HashMap<String, byte[]> expandedKeys = CryptoUtils.generateSecretKeys(clientNonce, dhMasterKey);

    // hmac of previous messages
    byte[] serverHMAC = CryptoUtils.generateHMAC("encrypt", expandedKeys.get("serverMAC"));
    boolean isServerHMACValid = CryptoUtils.verifyHMAC("encrypt",serverHMAC, expandedKeys.get("serverMAC"));
    // System.out.println("isServerHMACValid: " + isServerHMACValid);

    // hmac of previous messages
    byte[] clientHMAC = CryptoUtils.generateHMAC("encrypt", expandedKeys.get("clientMAC"));
    boolean isClientHMACValid = CryptoUtils.verifyHMAC("encrypt",clientHMAC, expandedKeys.get("clientMAC"));
    // System.out.println("isClientHMACValid: " + isClientHMACValid);

    // encrypt message
    byte[] serverDecrypt = new byte[0];
    try {
      byte[] serverCipher = CryptoUtils.encryptMessage("hello jun", expandedKeys.get("serverEncrypt"), expandedKeys.get("serverIV"), expandedKeys.get("serverMAC"));
      serverDecrypt = CryptoUtils.decryptMessage(serverCipher, expandedKeys.get("serverEncrypt"), expandedKeys.get("serverIV"), expandedKeys.get("serverMAC"));
    } catch (Exception e) {
      e.printStackTrace();
    }
    String serverPlaintxt = CryptoUtils.bytesToString(serverDecrypt);
    System.out.println("serverPlaintext: " + serverPlaintxt);


    // System.out.println("serverEncrypt: " + CryptoUtils.bytesToHex(expandedKeys.get("serverEncrypt")));
    // System.out.println("clientEncrypt: " + CryptoUtils.bytesToHex(expandedKeys.get("clientEncrypt")));
    // System.out.println("serverMAC: " + CryptoUtils.bytesToHex(expandedKeys.get("serverMAC")));
    // System.out.println("clientMAC: " + CryptoUtils.bytesToHex(expandedKeys.get("clientMAC")));
    // System.out.println("serverIV: " + CryptoUtils.bytesToHex(expandedKeys.get("serverIV")));
    // System.out.println("clientIV: " + CryptoUtils.bytesToHex(expandedKeys.get("clientIV")));

    
    


    // System.out.println("serverMasterKey: " + CryptoUtils.bytesToHex(serverMasterKey));
    // System.out.println("clientMasterKey: " + CryptoUtils.bytesToHex(clientMasterKey));

    // System.out.println("isServerCertValid: " + isServerCertValid);
    // System.out.println("isClientCertValid: " + isClientCertValid);

    // if (!isServerDHvalid || !isClientDHvalid) {
    //   System.out.println("DH public keys are not valid");
    // }else {
    //   System.out.println("DH public keys are valid");
    // }

    // System.out.println("CA Certificate:");
    // System.out.println(CACert);
    // System.out.println("------------------------");
    // System.out.println("Client Certificate:");
    // System.out.println(clientCert);
    // System.out.println("------------------------");

    // System.out.println("Server Certificate:");
    // System.out.println(serverCert);
    // System.out.println("------------------------");

    // System.out.println("dhClientPubKey:");
    // System.out.println(dhClientPubKey);
    // System.out.println("------------------------");

    // System.out.println("dhClientPrivKey:");
    // System.out.println(dhClientPrivKey);
    // System.out.println("------------------------");

    // System.out.println("dhServerPubKey:");
    // System.out.println(dhServerPubKey);
    // System.out.println("------------------------");

    // System.out.println("dhServerPrivKey:");
    // System.out.println(dhServerPrivKey);
    // System.out.println("------------------------");

    // System.out.println("Client Nonce:");
    // System.out.println(clientNonceHex);
    // System.out.println("------------------------");

    
  }
}