import re
import OpenSSL
import base64
import struct
import json
import six
import pkg_resources
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


class BootIntegrityValidator(object):
    """
    Validates
    """
    class BaseException(Exception):
        """
        Base Exception for all exceptions this class will raise
        """
    class ValidationException(BaseException):
        """
        Validation was attempted but failed
        """


    def __init__(self, known_good_values, known_good_values_signature=None, signing_cert=None):
        """
        Accepts the known_good_values dictionary and then validates the signature if given

        :param known_good_values: file like object containing JSON that is the KGV
        :param known_good_values_signature: file like object containing the signature of the file above
        :param signing_cert_filename: file like object containing the signing_cert
        """

        # Boot strap Trusted Root and then validate Sub-CAs

        self._trusted_store = None
        self._cert_obj = {}
        try:
            self._bootstrap_trusted_cas()
        except OpenSSL.crypto.X509StoreContextError as e:
            # oops!
            raise

        if signing_cert:
            self._validate_custom_cert(custom_cert=signing_cert)

        # Validate the known_good_valuescrca2048_obj object if known_good_values_signature provided
        if known_good_values_signature:
            try:
                self._validate_kgv_input_signature(kgv=known_good_values,
                                                   kgv_signature=known_good_values_signature,
                                                   custom_signing_cert=True if signing_cert else False)
            except OpenSSL.crypto.Error as e:
                raise BootIntegrityValidator.ValidationException("The known_good_values failed signature failed signature validation")

    def _bootstrap_trusted_cas(self):
        """

        :return:
        """
        package_name = __name__
        package_cert_path = '/certs'

        # Load the O=Cisco Systems, CN=Cisco Root CA 2048 tree first
        crca2048_obj = self._load_cert_from_stream(pkg_resources.resource_stream(package_name, package_cert_path + "/crca2048.pem"))
        act2sudica_obj = self._load_cert_from_stream(pkg_resources.resource_stream(package_name, package_cert_path + "/ACT2SUDICA.pem"))

        # Validate the act2sudica against the root and add both to store if passed validation
        self._trusted_store = OpenSSL.crypto.X509Store()
        self._trusted_store.add_cert(cert=crca2048_obj)
        self._cert_obj['crca2048'] = crca2048_obj
        store_ctx = OpenSSL.crypto.X509StoreContext(store=self._trusted_store, certificate=act2sudica_obj)
        store_ctx.verify_certificate()
        self._trusted_store.add_cert(cert=act2sudica_obj)
        self._cert_obj['ACT2SUDICA'] = act2sudica_obj

        # Load the O=Cisco, CN=Cisco Root CA M2 tree
        crcam2_obj = self._load_cert_from_stream(pkg_resources.resource_stream(package_name, package_cert_path + "/crcam2.pem"))
        innerspace_obj = self._load_cert_from_stream(pkg_resources.resource_stream(package_name, package_cert_path + "/innerspace.cer"))
        kgv_obj = self._load_cert_from_stream(pkg_resources.resource_stream(package_name, package_cert_path + "/Known_Good_Values_PROD.pem"))
        self._trusted_store.add_cert(cert=crcam2_obj)
        self._cert_obj['crcam2']  = crcam2_obj
        store_ctx = OpenSSL.crypto.X509StoreContext(store=self._trusted_store, certificate=innerspace_obj)
        store_ctx.verify_certificate()
        self._trusted_store.add_cert(cert=innerspace_obj)
        self._cert_obj['innerspace'] = innerspace_obj
        store_ctx = OpenSSL.crypto.X509StoreContext(store=self._trusted_store, certificate=kgv_obj)
        store_ctx.verify_certificate()
        self._trusted_store.add_cert(cert=kgv_obj)
        self._cert_obj['Known_Good_Values_PROD'] = kgv_obj

    def _validate_custom_cert(self, custom_cert):
        """

        :param custom_cert_filename: file-like obj containing custom signing cert
        :return:
        """
        custom_cert_obj = self._load_cert_from_stream(custom_cert)
        store_ctx = OpenSSL.crypto.X509StoreContext(store=self._trusted_store, certificate=custom_cert_obj)
        store_ctx.verify_certificate()
        self._trusted_store.add_cert(cert=custom_cert_obj)
        self._cert_obj['custom'] = custom_cert_obj

    def _validate_kgv_input_signature(self, kgv, kgv_signature, custom_signing_cert):
        """
        Validates the KGV input file against the signature using Known_Good_Values_PROD.cer if no other provided
        :param kgv:
        :param kgv_signature:
        :return:
        """
        signing_cert = self._cert_obj['custom'] if custom_signing_cert else self._cert_obj['Known_Good_Values_PROD']
        OpenSSL.crypto.verify(cert=signing_cert, signature=kgv_signature, data=kgv, digest="sha512")

    @staticmethod
    def _load_cert_from_stream(f):
        """
        Returns OpenSSL.x509 Ojbect read from a file-like
        :param f:
        :return:
        """
        return OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_PEM, buffer=f.read())

    @staticmethod
    def _load_cert_from_file(filename):
        """
        Returns OpenSSL.x509 Object read from file called filename
        :param filename: string of filename
        :return: OpenSSL.x509 Object
        """
        assert isinstance(filename, six.string_types), "filename should have been a string type"
        with open(filename, "rb") as f:
            return OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_PEM, buffer=f.read())

    def validate(self, show_platform_integrity_cmd_output, show_platform_sudi_certificate_cmd_output):
        """

        :param show_platform_integrity_cmd_output:
        :param show_platform_sudi_certificate_cmd_output:
        :return:
        """


    def _validate_device_cert(self, cmd_output):
        """
        :param cmd_output: This is the command output

        example input
        isr4321#show platform sudi certificate sign nonce 1
        -----BEGIN CERTIFICATE-----
        MIIDQzCCAiugAwIBAgIQX/h7KCtU3I1CoxW1aMmt/zANBgkqhkiG9w0BAQUFADA1
        ....
        kxpUnwVwwEpxYB5DC2Ae/qPOgRnhCzU=
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        MIIEPDCCAySgAwIBAgIKYQlufQAAAAAADDANBgkqhkiG9w0BAQUFADA1MRYwFAYD
        ....
        0IFJZBGrooCRBjOSwFv8cpWCbmWdPaCQT2nwIjTfY8c=
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        MIIDejCCAmKgAwIBAgIDMEqgMA0GCSqGSIb3DQEBCwUAMCcxDjAMBgNVBAoTBUNp
        ....
        IAFBbdvdOwLEVVBc76g74H7zJDkv9VtVtOZk0Ft5
        -----END CERTIFICATE-----
        Signature version: 1
        Signature:
        B1D5EA8BC99C5C7F7F19E0A10B60D7BEC904A66BCFD495A4BC45FF55F137F35F644F730120F74F17FAC88555304A28686699259A7AE772331917A51D66FFBF1122F6D757C7EE430D33F0B79507696570E19C92EEC6033F2CCB5E24EA9BC7CAF0274D1BF3EE3419A3B3C55AB62B95B2FE6D4FAFFEF2D62ADB8A782E14EB3C92DB2E72DB3D3FC1D2CF91DBFBBDE82A4A03BD505FE1AB109976C20AC58D651EF30D80D757832D12AAAD49DC6FF7DCAD4E28D9E22875FC3D157A4FF185313DF05831706505FE7CAF2BEFD5579EA182D1A9C70AE1788D3C539DE7ACC1E3FDDD800E08DB88C29C7B010E6A053622079B4DF476DE5D07AE6AAF2BEC4DCE63F2AA1C1DD2
        jyoungta-isr4321#

        :return: bool (validate or not),
                 OpenSSL.crypto.x509 cisco_ca,
                 OpenSSL.crypto.x509 cisco_sudi_ca,
                 OpenSSL.crypto.x509 device_sudi,
        """

        assert isinstance(cmd_output, six.string_types), "cmd_output is not an string type: %r" % type(cmd_output)

        known_good_cisco_ca = ("-----BEGIN CERTIFICATE-----\n"
                               "MIIDQzCCAiugAwIBAgIQX/h7KCtU3I1CoxW1aMmt/zANBgkqhkiG9w0BAQUFADA1\n"
                               "MRYwFAYDVQQKEw1DaXNjbyBTeXN0ZW1zMRswGQYDVQQDExJDaXNjbyBSb290IENB\n"
                               "IDIwNDgwHhcNMDQwNTE0MjAxNzEyWhcNMjkwNTE0MjAyNTQyWjA1MRYwFAYDVQQK\n"
                               "Ew1DaXNjbyBTeXN0ZW1zMRswGQYDVQQDExJDaXNjbyBSb290IENBIDIwNDgwggEg\n"
                               "MA0GCSqGSIb3DQEBAQUAA4IBDQAwggEIAoIBAQCwmrmrp68Kd6ficba0ZmKUeIhH\n"
                               "xmJVhEAyv8CrLqUccda8bnuoqrpu0hWISEWdovyD0My5jOAmaHBKeN8hF570YQXJ\n"
                               "FcjPFto1YYmUQ6iEqDGYeJu5Tm8sUxJszR2tKyS7McQr/4NEb7Y9JHcJ6r8qqB9q\n"
                               "VvYgDxFUl4F1pyXOWWqCZe+36ufijXWLbvLdT6ZeYpzPEApk0E5tzivMW/VgpSdH\n"
                               "jWn0f84bcN5wGyDWbs2mAag8EtKpP6BrXruOIIt6keO1aO6g58QBdKhTCytKmg9l\n"
                               "Eg6CTY5j/e/rmxrbU6YTYK/CfdfHbBcl1HP7R2RQgYCUTOG/rksc35LtLgXfAgED\n"
                               "o1EwTzALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJ/PI\n"
                               "FR5umgIJFq0roIlgX9p7L6owEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQEF\n"
                               "BQADggEBAJ2dhISjQal8dwy3U8pORFBi71R803UXHOjgxkhLtv5MOhmBVrBW7hmW\n"
                               "Yqpao2TB9k5UM8Z3/sUcuuVdJcr18JOagxEu5sv4dEX+5wW4q+ffy0vhN4TauYuX\n"
                               "cB7w4ovXsNgOnbFp1iqRe6lJT37mjpXYgyc81WhJDtSd9i7rp77rMKSsH0T8lasz\n"
                               "Bvt9YAretIpjsJyp8qS5UwGH0GikJ3+r/+n6yUA4iGe0OcaEb1fJU9u6ju7AQ7L4\n"
                               "CYNu/2bPPu8Xs1gYJQk0XuPL1hS27PKSb3TkL4Eq1ZKR4OCXPDJoBYVL0fdX4lId\n"
                               "kxpUnwVwwEpxYB5DC2Ae/qPOgRnhCzU=\n"
                               "-----END CERTIFICATE-----").strip()

        known_good_cisco_sudi_ca = ("-----BEGIN CERTIFICATE-----\n"
                                    "MIIEPDCCAySgAwIBAgIKYQlufQAAAAAADDANBgkqhkiG9w0BAQUFADA1MRYwFAYD\n"
                                    "VQQKEw1DaXNjbyBTeXN0ZW1zMRswGQYDVQQDExJDaXNjbyBSb290IENBIDIwNDgw\n"
                                    "HhcNMTEwNjMwMTc1NjU3WhcNMjkwNTE0MjAyNTQyWjAnMQ4wDAYDVQQKEwVDaXNj\n"
                                    "bzEVMBMGA1UEAxMMQUNUMiBTVURJIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"
                                    "MIIBCgKCAQEA0m5l3THIxA9tN/hS5qR/6UZRpdd+9aE2JbFkNjht6gfHKd477AkS\n"
                                    "5XAtUs5oxDYVt/zEbslZq3+LR6qrqKKQVu6JYvH05UYLBqCj38s76NLk53905Wzp\n"
                                    "9pRcmRCPuX+a6tHF/qRuOiJ44mdeDYZo3qPCpxzprWJDPclM4iYKHumMQMqmgmg+\n"
                                    "xghHIooWS80BOcdiynEbeP5rZ7qRuewKMpl1TiI3WdBNjZjnpfjg66F+P4SaDkGb\n"
                                    "BXdGj13oVeF+EyFWLrFjj97fL2+8oauV43Qrvnf3d/GfqXj7ew+z/sXlXtEOjSXJ\n"
                                    "URsyMEj53Rdd9tJwHky8neapszS+r+kdVQIDAQABo4IBWjCCAVYwCwYDVR0PBAQD\n"
                                    "AgHGMB0GA1UdDgQWBBRI2PHxwnDVW7t8cwmTr7i4MAP4fzAfBgNVHSMEGDAWgBQn\n"
                                    "88gVHm6aAgkWrSugiWBf2nsvqjBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vd3d3\n"
                                    "LmNpc2NvLmNvbS9zZWN1cml0eS9wa2kvY3JsL2NyY2EyMDQ4LmNybDBQBggrBgEF\n"
                                    "BQcBAQREMEIwQAYIKwYBBQUHMAKGNGh0dHA6Ly93d3cuY2lzY28uY29tL3NlY3Vy\n"
                                    "aXR5L3BraS9jZXJ0cy9jcmNhMjA0OC5jZXIwXAYDVR0gBFUwUzBRBgorBgEEAQkV\n"
                                    "AQwAMEMwQQYIKwYBBQUHAgEWNWh0dHA6Ly93d3cuY2lzY28uY29tL3NlY3VyaXR5\n"
                                    "L3BraS9wb2xpY2llcy9pbmRleC5odG1sMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJ\n"
                                    "KoZIhvcNAQEFBQADggEBAGh1qclr9tx4hzWgDERm371yeuEmqcIfi9b9+GbMSJbi\n"
                                    "ZHc/CcCl0lJu0a9zTXA9w47H9/t6leduGxb4WeLxcwCiUgvFtCa51Iklt8nNbcKY\n"
                                    "/4dw1ex+7amATUQO4QggIE67wVIPu6bgAE3Ja/nRS3xKYSnj8H5TehimBSv6TECi\n"
                                    "i5jUhOWryAK4dVo8hCjkjEkzu3ufBTJapnv89g9OE+H3VKM4L+/KdkUO+52djFKn\n"
                                    "hyl47d7cZR4DY4LIuFM2P1As8YyjzoNpK/urSRI14WdIlplR1nH7KNDl5618yfVP\n"
                                    "0IFJZBGrooCRBjOSwFv8cpWCbmWdPaCQT2nwIjTfY8c=\n"
                                    "-----END CERTIFICATE-----").strip()

        # Extract certs from output
        certs = re.findall(r"((?:-{5}BEGIN\s+CERTIFICATE-{5}).+?(?:-{5}END\s+CERTIFICATE-{5}))", cmd_output, flags=re.DOTALL)

        # Compare CA against known good CA
        ca_cert_text = certs[0]
        if not ca_cert_text == known_good_cisco_ca:
            raise Exception("Root Cert mismatch")
        ca_cert_obj = OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_PEM, buffer=ca_cert_text.encode())

        # Compare Sub-CA against known good sub-CA
        cisco_sudi_ca_text = certs[1]
        if not cisco_sudi_ca_text == known_good_cisco_sudi_ca:
            raise Exception("Sub-Ca Cert mismatch")
        cisco_sudi_ca_obj = OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_PEM, buffer=cisco_sudi_ca_text.encode())

        # Device sudi cert
        device_sudi_text = certs[2]
        device_sudi_obj = OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_PEM, buffer=device_sudi_text.encode())

        store = OpenSSL.crypto.X509Store()
        store.add_cert(cert=ca_cert_obj)

        # validate Sub-CA against Root
        store_ctx = OpenSSL.crypto.X509StoreContext(store=store, certificate=cisco_sudi_ca_obj)
        try:
            store_ctx.verify_certificate()
        except OpenSSL.crypto.X509StoreContextError as e:
            raise ValueError("sub-ca failed to validate against root")

        # Since Sub-CA is validated add it to the store
        store.add_cert(cert=cisco_sudi_ca_obj)
        store_ctx = OpenSSL.crypto.X509StoreContext(store=store, certificate=device_sudi_obj)

        # validate Device ID Certificate
        try:
            store_ctx.verify_certificate()
            validated = True
        except OpenSSL.crypto.X509StoreContextError as e:
            validated = False

        return validated, ca_cert_obj, cisco_sudi_ca_obj, device_sudi_obj