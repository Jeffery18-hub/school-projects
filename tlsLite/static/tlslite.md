# TLSlite

## Due Friday, March 29 — but with a checkpoint on Friday, March 15

For this project, we'll build a simplified version of the TLS protocol.  We'll stick fairly close to real TLS, but we'll leave out lots of options, simplify the message format, and rely on Java serialization to write and parse messages.

## Creating and signing certificates

We'll use three RSA public/private key pairs in our system:

- Certificate Authority (CA) — A keypair to sign and verify certificates for the client and server.  This our stand-in for a service like Versign or LetsEncrypt, but since we're inventing it, it's authoritative only to our client and server.
- Server — Needs a certificate signed by the CA and corresponding private key.  The server will use these to authenticate itself to the client while performing a handshake.
- Client — Same as the server, because we will implement an authenticated-client variant of TLS.

We'll use OpenSSL to generate our public/private key pairs and certificates.  A macOS installation includes OpoenSSL as `openssl`, and the following instructions have been tested with that version.  If you use the Homebrew version of `openssl`, things might be different.

### Create a working directory

We're going to create a bunch of files, so create a fresh directory and `cd` into that directory. This will be our *working directory*.

### Generate the RSA public/private key pair for the CA

In the working directory:

`openssl req -x509 -newkey rsa:4096 -keyout CAprivateKey.pem -out CAcertificate.pem -days 30 -nodes` 

Let's walk through this command:

- `req` — make a new certificate
- `-x509` — in x509 format (the standard format)
- `-newkey` — generate a new RSA keypair for this certificate
- `rsa:4096` — make it a 4096 bit RSA key
- `-keyout CAprivateKey.pem` — write the private key to `CAprivateKey.pem`
- `-out CAcertificate.pem` — write the certificate to `CAcertificate.pem`
- `-days 30` — this certificate expires 30 days from now
- `-nodes` — don't encrypt the certificate/private key

This command will take a while to run, because it has to find big prime numbers and do the other number theory stuff to pick the RSA exponents. It will generate new files in the working directory.

**Note for the 3 sets of keys we'll be making, the country name, state name, and organization name must be the same for all 3**.  For the CSR's (below), I'd suggest picking different common names for the client/server.  If don't enter the fields correctly, the certificate creation/signing part below will fail and openSSL will tell you why.

### Generate client/server keys  and certificate signature requests (CSRs)

Next we'll pick the keys for the client and server and a request for the CA to sign.

`openssl req -new -newkey rsa:4096 -nodes -keyout serverPrivate.key -out server.csr`

This command will produce the private key and the request for the CA to sign for the server.  
You'll need to use a similar command for the client with file names using `client`  
instead of `server`.

### Setup CA for signing, sign CSRs

Download [this CA config file](config.cnf) as `config.cnf` in your working directory.  The file specifies a bunch of information for the CA — almost all of which is overkill for us, but it seems to be necessary. The configuration file specifies files and directories that need to exist to sign the CSRs and produce client and server certificates.

```sh
mkdir certs newcerts
touch index.txt
echo 1000 > serial
```

The file `index.txt` is the "database" that lists all the certificates that have been issued by our CA. (Again, this is overkill for us, but it makes OpenSSL happy.)  
The `serial` file keeps track of the serial numbers assigned to those certificates, since that number needs to be unique per certificate issued.

At this point, we can fulfill a CSR request:

`openssl ca -config config.cnf  -cert CAcertificate.pem -keyfile CAprivateKey.pem -in server.csr -out CASignedServerCertificate.pem`

That's for the server, and you'll need a similar command for the client (with different file names). This command will take the CA certificate, CA private key, and CSR and will produce a certificate signed by our CA.  Note that pretty much the only field that you'll be prompted to enter that really matters is the "common name."  The `index.txt` file ensures that the CA does NOT sign multiple certificates for the same common name, so make sure you pick different names for the client and server.

### Double checking

Our certificate files *should* be contain the server's or client's public key.  To verify that each matches its private key, we can confirm that the modulus (the big N) is the same for a certificate and the private key.  We can use `openssl sa` to do compare.  Because N is huge, we run the output of `openssl rsa` through a hash function and compare the hashes.

For the client, check that reading the private key with

`openssl rsa -in clientPrivate.key -noout -modulus | openssl sha256`

and reading the certificate

`openssl x509 -noout -modulus -in CASignedClientCertificate.pem | openssl sha256`

produce the same hash. Check the server's private key and certificate with suitably adjusted commands.

### Formats

OpenSSL produces PEM format private key files, which is a text-based format that is a pain to work with Java. The DER binay format is easier to work with.  We can use OpenSSL to convert our PEM private keys to DER private keys:

`openssl pkcs8 -topk8 -outform DER -in serverPrivate.key -out serverPrivateKey.der -nocrypt`

### Checkpoint due March 15

On [Canvas](https://utah.instructure.com/courses/932589/assignments/13966621), submit brief text that lists:

- The name of each file created by this set-up that is needed for your TLSlite client and server.
- Which programs will read each **file**: client, server, or both. Note that "none" is not an option here; don't mention files that won't be needed at run time. Also, this is not about which side needs the data eventually, but which side actually reads the data from a file as opposed to a network connection.
- A one-line description of each file's content/role.

This checkpoint is worth 10% of your grade for the assignment, and *the deadline is strict:* 11:59:59pm on March 15.

## Handshake

At this point, we have the CA, certificates, and associated keys generated: *serverRSAPriv* (in the server private-key file), *serverRSAPub* (in the server certificate file), *clientRSAPriv* (in the client private-key file), and *clientRSAPub* (in the client certificate file). Those are generated just once and used for every communication.

The server and client will also agree on Diffie-Hellman parameters *g* and *N*. On each new connection from client to server, the server and client will pick random secret keys to use with Diffie-Hellman, which we'll call *serverDHPriv* for the server and *clientDHPriv* for the client. The public keys can be derieved: *serverDHPub* = *g*^*serverDHPriv* mod *N* and *clientDHPub* = *g*^*clientDHPriv* mod *N*.

Finally, the client will pick a random *nonce* for each connection (in addition to its Diffie-Hellman private key). The *nonce* can be 32 bytes from a `SecureRandom` object.

The client and server will each authenticate each other using a simplified TLS handshake as follows:

- Client: sends *nonce*
- Server: sends the server certificate, *serverDHPub*, and a signed Diffie-Hellman public key as Enc(*serverRSAPriv*, *serveDHPub*)  

  > *sign the serverDHPub key with its own serverRSAPrivate key to make sure the serverDHPub is sent by server.* 

- Client: sends a client certificate, a Diffie-Hellman public key, and a signed Diffie-Hellman public key as Enc(*clientRSAPriv*, *clientDHPub*)

At this point, the client and server can each check that the received certificate is valid according to the CA that they both know. The client and server can also compute the shared Diffie-Hellman secret. Using that shared secret as the master key, the client and server can then compute 6 session keys via a HKDF: 2 each of encryption keys, MAC keys, and initialization vectors (IVs) for CBC.

> six keys:  3 are used by client msg encypt and decrypt and 3 are used by server.

Finish the handshake with two more messages:

- Server: sends HMAC of all handshake messages so far using the server's MAC key.
- Client: sends HMAC of all handshake messages so far (including the previous step) using the clients's MAC key.

> MAC: msg authentication code -> the code is generated with msgs and mac key and is used for msg integrity and auth as well. Hash fucntions do not need the key as the input but only the msg itself.

At this point, the client and server have authenticated.

### Key generation: HKDF

Diffie-Hellman gives us a shared secret key, but it might be too small or be otherwise unsuitable to use as keys for AES or MACs.  We'll run it through a key derivation function (KDF) to turn it into a bunch of nice, random-looking keys. Specifically, we'll use HKDF, and the *nonce* is used to start the HMAC sequence as sketched by this pseudocode:

````
function hdkfExpand(input, tag): // tag is a string, but that's easily converted to byte[]
   okm = HMAC(key = input,  data = tag concatenated with a byte with value 1)
   return first 16 bytes of okm

function makeSecretKeys(clientNonce, sharedSecretFromDiffieHellman):
   prk = HMAC(key = clientNonce, data = sharedSecretFromDiffieHellman)
   serverEncrypt = hkdfExpand(prk, "server encrypt")
   clientEncrypt = hkdfExpand(serverEncrypt, "client encrypt")
   serverMAC = hkdfExpand(clientEncrypt, "server MAC")
   clientMAC = hkdfExpand(serverMAC, "client MAC")
   serverIV = hkdfExpand(clientMAC, "server IV")
   clientIV = hkdfExpand(serverIV, "client IV")
````

So, each key is essentially the result of hashing one of the other keys and adding in an extra "tag" to make sure they can't accidentally be mistaken for one another.  Use the `HmacSHA256` HMAC function.

Note, that Java has special types for the various types of secret keys.  For many keys, you'll probably want to use the `SecretKeySpec` class to make a `SecretKey` instance. The `SecretKeySpec` constructor takes bytes and turns it into a key for a given algorithm — which doesn't change the value of the key, but marks its intended use.  For IVs, use the `IvParameterSpec` class, instead.

## Message format

After the handshake, each message will use a format similar to the TLS record format, but we'll let Java take care of the specifics by making use of the `ObjectOutputStream` and `ObjectInputStream` classes.

To send a message:

- Compute the HMAC of the message using the appropriate MAC key
- Use the cipher object to encrypt the message data concatenated with the MAC
- Send/receive the resulting byte array using the `ObjectOutputStream`/`ObjectIntputStream` classes (it will include the array size, etc automatically).  You'll want to use the `readObject`/`writeObject` methods.

For encryption, we'll use AES 128 in CBC mode.  For MAC, we'll use HMAC using SHA-256 as our hash function.

## Code and testing

Write 2 programs, a client a server. Consider organizing your code as a single Java project with multiple classes that have `main()` methods.

The server should open a plain TCP server socket and listen for connections.  After it accepts a new connection as a socket one, it should handshake with the client and then send multiple (at least two) messages to the client. The handshake part is inherent, while the additional messages act as tests to make sure that things work properly.

The client should handshake and then receive the messages. It should then send a message back to the server to indicate that it received the messages and in a way  that indicates that it received the right messages.  This step checks that we can actually send messages in both directions.

Note that the client and server should both read the CA certificate as well as their own certificates and private keys.  *Neither should read the other host's certificate/keys from files*.  The parties need to send the certificates to each other as part of the handshake protocol, and they should never access each other's private keys.

## Suggestions:

- Use the 2048-bit Diffie Hellman group (*g* and *N*) from [RFC 3526](https://www.ietf.org/rfc/rfc3526.txt).
- Start by having the client and server be part of the same non-networking program with comments to track which parts perform client tasks and which perform server tasks.  After all of the crypto stuff works without sockets, reorganize and add the networking part.
- There will be lots of shared code between the client/server, so factor it out. For example, you may have classes with static methods related to Diffie-Hellman, key generation, handshake operations, and message encryption.

The following Java classes will be useful:

- `BigInteger` for Diffie-Hellman
- `java.security.cert.CertificateFactory`
- `java.security.cert.Certificate`
- `java.security.SecureRandom`
- `javax.crypto.Cipher` with `"RSA/ECB/PKCS1Padding"` and `"AES/CBC/PKCS5Padding"`
- `javax.crypto.Mac`
- `javax.crypto.SecretKey`
- `javax.crypto.spec.SecretKeySpec` with `"RawBytes"` and `"AES"`
- `javax.crypto.spec.IvParameterSpec`
- `java.security.spec.PKCS8EncodedKeySpec` for loading secret keys
- `java.security.KeyFactory` to convert an RSA private key spec to a key
- `ByteArrayOutputStream`
- `ObjectOutputStream` and `ObjectInputStream`

This is not an exhaustive list, however.

Some [code showing how to use some of the above classes](http://tutorials.jenkov.com/java-cryptography/signature.html) may be helpful.