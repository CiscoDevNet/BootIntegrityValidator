The Root and Sub-CA certificates loaded here can be retrieved from http://www.cisco.com/security/pki/

PKI Infrastructure used to validate the signed output from the device CLI

(crca2048.pem)
O=Cisco Systems, CN=Cisco Root CA 2048
  |
  |   (ACT2SUDICA.pem)
  +----O=Cisco, CN=ACT2 SUDI CA


(crca2099.pem)
O=Cisco, CN=Cisco Root CA 2099
  |
  |    (hasudi.pem)
  +----CN=High Assurance SUDI CA, O=Cisco


PKI Infrastructure used to validate the signed KGV file
(crcam2.pem)
O=Cisco, CN=Cisco Root CA M2
  |
  |   (innerspace.cer)
  +----O=Cisco, CN=Innerspace SubCA RSA
         |
         |    (Known_Good_Values_PROD.cer)
         +----CN=KnownGoodValuesPROD, OU=REL, O=Cisco



