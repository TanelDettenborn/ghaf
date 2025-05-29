README

!! Proof of concept and therefore some of the stuff are hardcoded !!

- Not optimized
- For convenience run as root user
- Hash is hardcoded for 384
- Prints keys into uart -> slow
- All sign commands runned on device

Quick guide
-----------

0. Generate test data and put it into file "data"
  $ echo "My test data" > data

1. Import/Export identity key into HSM
  $ sudo gen-exp-identity-key

2. Test(s)

* pkcs11-tool sign and pkcs11-tool verify
  $ pkcs11-tool-optee --sign --pin 0000 --id 11 -m ECDSA-SHA384 -i data -o data.sig
  $ pkcs11-tool-optee --verify --pin 0000 -m ECDSA-SHA384 --id 11 -i data --signature-file data.sig

* PKCS11-tool sign and openssl verify
  $ pkcs11-tool-optee --sign --pin 0000 --id 11 -m ECDSA-SHA384 --signature-format openssl -i data -o data.sig
  $ openssl dgst -sha384 -verify pub-Drone-HW-derived-identity-key.key -signature data.sig data

* TA signs and openssl verify
  $ sudo poc-identity-key-sign-data-file
  $ openssl dgst -sha384 -verify pub-Drone-HW-derived-identity-key.key -signature signature.der data
