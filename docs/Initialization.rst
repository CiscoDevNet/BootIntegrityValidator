.. _Initialization:

Initialization
==============

The BootIntegrityValidation object gets initialized by passing in a bytes object that contains the known good values.
Typically this is an UTF-8 encoded JSON file that would be read from the OS, however it was intentionally left as a
pure bytes input as the KGVs might be a static file obtained from Cisco or data received from an API.

An example KGV file can be found here examples/example_kgv.json file with a format similar to below.

.. code-block:: json

    {
       "header":{
          "version":"KGV_format_2.0"
       },
       "products":[
          {
             "product":"ISR4K",
             "bootLoaderVersions":[
                {
                   "version":"16.4(3r)",
                   "entries":[
                      {
                         "biv_hash":"65EF4FDBAA6533E50BAF02D25F0E1C14EF02397B1333E0F476DF59ECEC5F2B1D41A06FB4B25F3150E8460F66CE6A58C81F261CF5433880243644E0E277D8C737",
                         "published":"May 14 2017 19:00:28 PDT-0700"
                      },
                      {
                         "biv_hash":"65EF4FDBAA6533E50BAF02D25F0E1C14EF02397B1333E0F476DF59ECEC5F2B1D41A06FB4B25F3150E8460F66CE6A58C81F261CF5433880243644E0E277D8C737",
                         "published":"May 14 2017 19:00:29 PDT-0700"
                      }
                   ]
                }
             ],
             "boot0Versions":[
                {
                   "version":"F01001R06.03c1d3d202013-01-18",
                   "entries":[
                      {
                         "biv_hash":"82597CE130610B8016A6A0FF2851919279857C86966540170E1132C6872A6274",
                         "published":"May 14 2017 19:00:28 PDT-0700"
                      }
                   ]
                }
             ],
             "osImageVersions":[
                {
                   "version":"16.02.01",
                   "entries":[
                      {
                         "sha512":"ccb1142f3a34957319b47063e303adecbe86c9c7a9bc00e78aee5d7f8b79f57a71569deeb7493aa6b027199ae0f0c18bb9fd012c090a7cbc8fe7e8af9569566f",
                         "biv_hash":"2F60A0AE7FC1B82AD9D8E140171BE529A103F6274ACDD00D2305B01C79ACED2E4911BCAE1B30867AF290CF48AB3A42BACF58E1198A2FBB546FA5F5E7BF5352C0",
                         "sha1":"1a51ffc29ca5c5db096ce6d3f7338852bf019d5d",
                         "filename":"isr4300-universalk9_npe.16.02.01.SPA.bin",
                         "md5":"53d7d7e525dcbfc4fc9dc573d4d8e89d",
                         "published":"May 14 2017 19:16:11 PDT-0700",
                         "sha256":"66af3d190fc70a6a3a69d4855441f77e249b457e5b4c5db6b57eb74f12c79a41"
                      }
                   ]
                }
             ]
          }
       ]
    }


To initialize the object call the constructor:

.. code-block::  python

    import BootIntegrityValidator

    kgv = open("example_kgv.json", "rb")
    biv = BootIntegrityValidator.BootIntegrityValidator(known_good_values=kgv.read())


The initialization function can optionally be provided a signature file.  The signature file is a signed hash of the known good values file.
The signature is provided by a signing certificate issued by Cisco.

By default the object is expecting the signature to be signed by "CN=KnownGoodValuesPROD, OU=REL, O=Cisco" but can optionally a custom
signing certficate can be provided in the initialization call

.. code-block:: text

    (crcam2.pem)
    O=Cisco, CN=Cisco Root CA M2
      |
      |   (innerspace.cer)
      +----O=Cisco, CN=Innerspace SubCA RSA
             |
             |    (Known_Good_Values_PROD.cer)
             +----CN=KnownGoodValuesPROD, OU=REL, O=Cisco


Copies of the Cisco CA Roots are included in the BootIntegrityValidator/certs folder and can also be obtained directly
from `Cisco <http://www.cisco.com/security/pki/>`_

Example how to specify the signature and/or the custom signing:

.. code-block::  python

    import BootIntegrityValidator

    # Provide the signature file
    kgv = open("example_kgv.json", "rb")
    kgv_sig = open("example_kgv.json.signature", "rb")
    biv = BootIntegrityValidator.BootIntegrityValidator(known_good_values=kgv.read(),
                                                        known_good_values_signature=kgv_sig.read())

    # Provide signature file (as bytes)
    # and custom signing certificate (as a file-like object)
    kgv = open("example_kgv.json", "rb")
    kgv_sig = open("example_kgv.json.signature", "rb")
    custom_cert = open("example_custom_cert.pem", "rb")
    biv = BootIntegrityValidator.BootIntegrityValidator(known_good_values=kgv.read(),
                                                        known_good_values_signature=kgv_sig.read(),
                                                        custom_signing_cert=custom_cert)


The initialization function will raise a **ValidationException** if the custom_signing_cert is not signed by the Cisco CAs