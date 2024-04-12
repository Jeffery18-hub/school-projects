# this cli is used to check the text content of certs
openssl x509 -in <CAcertificate.pem> -text -noout

# this cli is used to check the text content of private key
openssl rsa -in <serverPrivate.key> -text -noout