__author__ = "Jay Young"
__author_email__ = "jyoungta@cisco.com"
__copyright__ = "Copyright (c) 2021 Cisco Systems, Inc."
__license__ = "MIT"

import re
import logging
import base64
import struct
import json
import pkg_resources
import typing
import collections
import copy
import base64

import OpenSSL

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


class BootIntegrityValidator(object):
    """
    Validates the boot integrity visibility data for Cisco Products
    """

    class BaseException(Exception):
        """
        Base Exception for all exceptions this class will raise
        """

    class ValidationException(BaseException):
        """
        Validation was attempted but failed
        """

    class InvalidFormat(BaseException):
        """
        known_good_values is not structured correctly
        """

    class ProductNotFound(BaseException):
        """
        Product Not Found
        """

    class MissingInfo(BaseException):
        """
        Information in the "show platform" command output is missing.
        Like the hash output
        """

    Location = collections.namedtuple(
        "Location", ["fru", "slot", "bay", "chassis", "node"]
    )

    def __init__(
        self,
        known_good_values,
        known_good_values_signature=None,
        custom_signing_cert=None,
        log_level=logging.ERROR,
    ):
        """
        :param known_good_values: bytes - containing JSON that is the KGV
        :param known_good_values_signature: bytes - containing the signature of the file above
        :param custom_signing_cert: file like object containing the signing_cert
        :param log_level: Logging verbosity setting.  Set the level to one of the logging.INFO, DEBUG, ERROR, etc levels
        """
        assert log_level in (
            logging.CRITICAL,
            logging.ERROR,
            logging.WARNING,
            logging.INFO,
            logging.DEBUG,
        )
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(log_level)
        self._logger.info("Initializing BootIntegrityValidator object")

        assert isinstance(
            known_good_values, bytes
        ), f"known_good_value should be of type bytes, was {type(known_good_values)!r}"
        assert known_good_values_signature is None or isinstance(
            known_good_values_signature, bytes
        ), "known_good_value_signature should be None or bytes, was %r" % type(
            known_good_values_signature
        )
        # Boot strap Trusted Root and then validate Sub-CAs

        self._trusted_store = None
        self._cert_obj = {}
        self._bootstrap_trusted_cas()

        if custom_signing_cert:
            self._logger.debug(
                "Custom signing cert has been provided.  Not using built-in certs"
            )
            self._validate_custom_cert(custom_cert=custom_signing_cert)

        # Validate the known_good_valuescrca2048_obj object if known_good_values_signature provided
        if known_good_values_signature:
            self._logger.info(
                "Signature file provided.  Attempting to validate the KGV file"
            )
            self._validate_kgv_input_signature(
                kgv=known_good_values,
                kgv_signature=known_good_values_signature,
                custom_signing_cert=bool(custom_signing_cert),
            )

        else:
            self._logger.info(
                "No signature file provided.  Skipping KGV file validation"
            )

        # Now the known_good_values is validated try to load the json. If successful we are ready
        try:
            self._logger.info("Loading KGV values")
            self._kgv = json.loads(known_good_values.decode())
        except ValueError as e:
            self._logger.error("KGV file invalid.  Failed to load the values")
            raise BootIntegrityValidator.InvalidFormat(
                "The known_good_values appears to be invalid JSON"
            )

        self._logger.info("BootIntegrityValidator object successfully initiated")

    def _bootstrap_trusted_cas(self):
        """
        Reads in the Root Cisco CA Certs from within the package
        :return: None
        :raises: ValidationException if the Root or Sub-CA certs fail to validate
        """
        package_name = __name__
        package_cert_path = "/certs"

        self._logger.info("Bootstraping the trusted CA certificates")

        try:
            # Load the O=Cisco Systems, CN=Cisco Root CA 2048 tree first
            crca2048_obj = self._load_cert_from_stream(
                pkg_resources.resource_stream(
                    package_name, package_cert_path + "/crca2048.pem"
                )
            )
            act2sudica_obj = self._load_cert_from_stream(
                pkg_resources.resource_stream(
                    package_name, package_cert_path + "/ACT2SUDICA.pem"
                )
            )

            # Validate the act2sudica against the root and add both to store if passed validation
            self._trusted_store = OpenSSL.crypto.X509Store()
            self._trusted_store.add_cert(cert=crca2048_obj)
            self._cert_obj["crca2048"] = crca2048_obj
            self._logger.debug("Loaded the CRCA2048 root CA cert")
            store_ctx = OpenSSL.crypto.X509StoreContext(
                store=self._trusted_store, certificate=act2sudica_obj
            )
            store_ctx.verify_certificate()
            self._logger.debug(
                "Successfully validated the ACT2 SUDI CA cert against the CRCA2048"
            )
            self._trusted_store.add_cert(cert=act2sudica_obj)
            self._cert_obj["ACT2SUDICA"] = act2sudica_obj

            # Load the Cisco Root 2099 tree
            crca2099_obj = self._load_cert_from_stream(
                pkg_resources.resource_stream(
                    package_name, package_cert_path + "/crca2099.pem"
                )
            )
            hasudi_obj = self._load_cert_from_stream(
                pkg_resources.resource_stream(
                    package_name, package_cert_path + "/hasudi.pem"
                )
            )

            # Validate the High Assurance SUDI CA against the root and both to store if passed validation
            self._trusted_store.add_cert(cert=crca2099_obj)
            self._cert_obj["crca2099"] = crca2099_obj
            self._logger.debug("Loaded the CRCA2099 Root CA cert")
            store_ctx = OpenSSL.crypto.X509StoreContext(
                store=self._trusted_store, certificate=hasudi_obj
            )
            store_ctx.verify_certificate()
            self._logger.debug(
                "Successfully validated the HA SUDI CA cert against the CRCA2099"
            )
            self._trusted_store.add_cert(cert=hasudi_obj)
            self._cert_obj["hasudi"] = hasudi_obj

            # Load the O=Cisco, CN=Cisco Root CA M2 tree
            crcam2_obj = self._load_cert_from_stream(
                pkg_resources.resource_stream(
                    package_name, package_cert_path + "/crcam2.pem"
                )
            )
            innerspace_obj = self._load_cert_from_stream(
                pkg_resources.resource_stream(
                    package_name, package_cert_path + "/innerspace.cer"
                )
            )
            kgv_obj = self._load_cert_from_stream(
                pkg_resources.resource_stream(
                    package_name, package_cert_path + "/Known_Good_Values_PROD.pem"
                )
            )
            self._trusted_store.add_cert(cert=crcam2_obj)
            self._logger.debug("Loaded the Cisco Root CA M2 tree")
            self._cert_obj["crcam2"] = crcam2_obj
            store_ctx = OpenSSL.crypto.X509StoreContext(
                store=self._trusted_store, certificate=innerspace_obj
            )
            store_ctx.verify_certificate()
            self._logger.debug(
                "Validated the innerspace CA cert against the Cisco Root CA M2 tree"
            )
            self._trusted_store.add_cert(cert=innerspace_obj)
            self._cert_obj["innerspace"] = innerspace_obj
            store_ctx = OpenSSL.crypto.X509StoreContext(
                store=self._trusted_store, certificate=kgv_obj
            )
            store_ctx.verify_certificate()
            self._logger.debug(
                "Validated the KGV signing cert against the innerspace CA"
            )
            self._trusted_store.add_cert(cert=kgv_obj)
            self._cert_obj["Known_Good_Values_PROD"] = kgv_obj

        except Exception as e:
            self._logger.error("Validation/loading of the Cisco CA certs failed")
            raise BootIntegrityValidator.ValidationException(
                "Validation of Cisco CA certs failed"
            )

        self._logger.info("Bootstrapping the trusted CA certs complete")

    def _validate_custom_cert(self, custom_cert):
        """
        Validates the custom_cert against the Cisco CA Roots
        :param custom_cert_filename: file-like obj containing custom signing cert
        :return: None
        :raises: ValidationException if the custom_cert isn't signed by Cisco CAs
        """
        self._logger.info("Validating the custom signing cert")
        custom_cert_obj = self._load_cert_from_stream(custom_cert)
        store_ctx = OpenSSL.crypto.X509StoreContext(
            store=self._trusted_store, certificate=custom_cert_obj
        )
        try:
            store_ctx.verify_certificate()
        except OpenSSL.crypto.X509StoreContextError as e:
            self._logger.error("Validation of custom signing cert failed")
            raise BootIntegrityValidator.ValidationException(
                "Custom signing cert failed to validate against the Cisco CAs"
            )
        self._trusted_store.add_cert(cert=custom_cert_obj)
        self._cert_obj["custom"] = custom_cert_obj
        self._logger.info("Custom signing cert validation successful")

    def _validate_kgv_input_signature(self, kgv, kgv_signature, custom_signing_cert):
        """
        Validates the KGV input file against the signature using Known_Good_Values_PROD.cer if custom_signing_cert is False
        :param kgv: bytes of the kgv
        :param kgv_signature: bytes of the signature
        :return: None
        :raises:
        """
        self._logger.info("Validating KGV signature")
        signing_cert = (
            self._cert_obj["custom"]
            if custom_signing_cert
            else self._cert_obj["Known_Good_Values_PROD"]
        )
        try:
            if len(kgv_signature) == 512:
                self._logger.debug("KGV signature uses SHA512")
                OpenSSL.crypto.verify(
                    cert=signing_cert,
                    signature=kgv_signature,
                    data=kgv,
                    digest="sha512",
                )
            elif len(kgv_signature) == 256:
                self._logger.debug("KGV signature uses SHA256")
                OpenSSL.crypto.verify(
                    cert=signing_cert,
                    signature=kgv_signature,
                    data=kgv,
                    digest="sha256",
                )
            else:
                self._logger.error("KGV signature is invalid format")
                raise BootIntegrityValidator.InvalidFormat(
                    "The kgv_signature seems to be invalid, should be either a sha-2-256 or sha-2-512"
                )
        except OpenSSL.crypto.Error as e:
            self._logger.error("KGV signature validation failed")
            raise BootIntegrityValidator.ValidationException(
                "The known_good_values failed signature failed signature validation"
            )

        self._logger.info("KGV signature valid")

    @staticmethod
    def _load_cert_from_stream(f):
        """
        Returns OpenSSL.x509 Ojbect read from a file-like object
        :param f: file-like object
        :return: OpenSSL.x509 Object
        """
        return OpenSSL.crypto.load_certificate(
            type=OpenSSL.crypto.FILETYPE_PEM, buffer=f.read()
        )

    @staticmethod
    def _load_cert_from_file(filename):
        """
        Returns OpenSSL.x509 Object read from file called filename
        :param filename: string of filename
        :return: OpenSSL.x509 Object
        """
        assert isinstance(filename, str), "filename should have been a string type"
        with open(filename, "rb") as f:
            return OpenSSL.crypto.load_certificate(
                type=OpenSSL.crypto.FILETYPE_PEM, buffer=f.read()
            )

    def validate(
        self,
        show_platform_integrity_cmd_output,
        show_platform_sudi_certificate_cmd_output=None,
    ):
        """
        Takes the CLI output from 'show platform integrity' and validates the output against the KGV
        If show_platform_sudi_certificate_cmd_output is provided validate the signature on the command itself

        :param show_platform_integrity_cmd_output: string of cli output
        :param show_platform_sudi_certificate_cmd_output: string of cli output
        :return: None if successfully validated
        :raises: ValidationError-
                    - if version is in kgv but hashes don't match
                    - if signature on cli is bad
        :raises: InvalidFormat - if the format of the KGV is invalid
        :raises: ProductNotFound - Hardware platform not found in KGV
        """

        self._logger.info("Starting BIV validation")
        assert isinstance(
            show_platform_integrity_cmd_output, str
        ), "show_platform_integrity_cmd_output should be a string type was %r" % type(
            show_platform_integrity_cmd_output
        )
        assert show_platform_sudi_certificate_cmd_output is None or isinstance(
            show_platform_sudi_certificate_cmd_output, str
        ), (
            "show_platform_sudi_certificate_cmd_output should be a string type was %r"
            % type(show_platform_sudi_certificate_cmd_output)
        )

        if show_platform_sudi_certificate_cmd_output:
            # Validate the device certificate and signature on cli output if present
            self._validate_device_cert(
                cmd_output=show_platform_sudi_certificate_cmd_output
            )
        else:
            self._logger.info(
                "'show platform certificate' command output not provided.  Skipping validation of the signature"
            )

        self._validate_show_platform_integrity_cmd_output(
            cmd_output=show_platform_integrity_cmd_output
        )
        self._logger.info("BIV validation complete")

    def _validate_device_cert(self, cmd_output):
        """
        Validate the device certificate against the Cisco CA and the signature if present

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

        :return:
        """

        self._logger.info("Processing the 'show platform sudi certificate' output")
        assert isinstance(
            cmd_output, str
        ), f"cmd_output is not an string type: {type(cmd_output)!r}"

        crca2048 = self._cert_obj["crca2048"]
        act2sudica = self._cert_obj["ACT2SUDICA"]
        crca2099 = self._cert_obj["crca2099"]
        hasudi = self._cert_obj["hasudi"]

        # Extract certs from output
        certs = re.findall(
            r"((?:-{5}BEGIN\s+CERTIFICATE-{5}).+?(?:-{5}END\s+CERTIFICATE-{5}))",
            cmd_output,
            flags=re.DOTALL,
        )

        if not certs:
            self._logger.error("0 certificates found in the command output")
            raise BootIntegrityValidator.MissingInfo(
                "0 certificates found in in command output"
            )

        # Compare CA against known good CAs
        ca_cert_text = certs[0]
        ca_cert_obj = OpenSSL.crypto.load_certificate(
            type=OpenSSL.crypto.FILETYPE_PEM, buffer=ca_cert_text.encode()
        )

        def same_cert(a, b):
            a_bytes = OpenSSL.crypto.dump_certificate(
                type=OpenSSL.crypto.FILETYPE_ASN1, cert=a
            )
            b_bytes = OpenSSL.crypto.dump_certificate(
                type=OpenSSL.crypto.FILETYPE_ASN1, cert=b
            )
            return a_bytes == b_bytes

        if not any([same_cert(x, ca_cert_obj) for x in [crca2048, crca2099]]):
            self._logger.error(
                "Cisco Root CA in cmd_output doesn't match a known good Cisco Root CA"
            )
            raise BootIntegrityValidator.ValidationException(
                "Cisco Root CA in cmd_output doesn't match known good Cisco Root CA"
            )

        # Compare Sub-CA against known good sub-CA
        cisco_sudi_ca_text = certs[1]
        cisco_sudi_ca_obj = OpenSSL.crypto.load_certificate(
            type=OpenSSL.crypto.FILETYPE_PEM, buffer=cisco_sudi_ca_text.encode()
        )
        if not any([same_cert(x, cisco_sudi_ca_obj) for x in [act2sudica, hasudi]]):
            self._logger.error(
                "Cisco SUDI Sub-CA in cmd_output doesn't match known good Cisco SUDI CA"
            )
            raise BootIntegrityValidator.ValidationException(
                "Cisco SUDI Sub-CA in cmd_output doesn't match known good Cisco SUDI CA"
            )

        # Device sudi cert
        device_sudi_text = certs[2]
        device_sudi_obj = OpenSSL.crypto.load_certificate(
            type=OpenSSL.crypto.FILETYPE_PEM, buffer=device_sudi_text.encode()
        )

        # validate Device ID Certificate
        try:
            self._logger.info("Validating device certificate against Cisco CAs")
            store_ctx = OpenSSL.crypto.X509StoreContext(
                store=self._trusted_store, certificate=device_sudi_obj
            )
            store_ctx.verify_certificate()
            self._cert_obj["device"] = device_sudi_obj
        except OpenSSL.crypto.X509StoreContextError as e:
            self._logger.error(
                "Device ID Certificate failed validation against Cisco CA Roots"
            )
            raise BootIntegrityValidator.ValidationException(
                "Device ID Certificate failed validation against Cisco CA Roots"
            )

        self._logger.info("Device ID certificate successfully validated")
        # Validate signature if present
        if "Signature" in cmd_output:
            self._logger.info("Signature of output present.  Attempt to validate")
            self._validate_show_platform_sudi_output(
                cmd_output=cmd_output,
                ca_cert_object=ca_cert_obj,
                sub_ca_cert_object=cisco_sudi_ca_obj,
                device_cert_object=device_sudi_obj,
            )
            self._logger.info("Signature of output valid.")
        else:
            self._logger.info(
                "Signature of the 'show platform sudi certificate' command not present, skipping validation"
            )

        self._logger.info(
            "Processing the 'show platform sudi certificate' output complete"
        )

    @staticmethod
    def _validate_show_platform_sudi_output(
        cmd_output, ca_cert_object, sub_ca_cert_object, device_cert_object
    ):
        """
        Validates the signature of the output from show platform sudi sign nonce xxx output
        Must contain the command actually being executed in text if nonce is included

        :param cmd_output: str

        example input
        isr4321#show platform sudi certificate sign nonce 1
        -----BEGIN CERTIFICATE-----
        MIIDQzCCAiugAwIBAgIQX/h7KCtU3I1CoxW1aMmt/zANBgkqhkiG9w0BAQUFADA1
        ...output omitted..
        kxpUnwVwwEpxYB5DC2Ae/qPOgRnhCzU=
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        MIIEPDCCAySgAwIBAgIKYQlufQAAAAAADDANBgkqhkiG9w0BAQUFADA1MRYwFAYD
        ...output omitted...
        0IFJZBGrooCRBjOSwFv8cpWCbmWdPaCQT2nwIjTfY8c=
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        MIIDejCCAmKgAwIBAgIDMEqgMA0GCSqGSIb3DQEBCwUAMCcxDjAMBgNVBAoTBUNp
        ...output omitted...
        IAFBbdvdOwLEVVBc76g74H7zJDkv9VtVtOZk0Ft5
        -----END CERTIFICATE-----
        Signature version: 1
        Signature:
        B1D5EA8BC99C5C7F7F19E.......DF476DE5D07AE6AAF2BEC4DCE63F2AA1C1DD2
        isr4321#

        :param ca: Openssl.crypto.x509
        :param sub: openssl.crypto.x509
        :param device: Openssl.crypto.x509
        :return: None if sucessfully validatated
        :raises: ValidationException if signature failed valiation
        """

        assert isinstance(
            cmd_output, str
        ), f"cmd_output is not an string type: {type(cmd_output)!r}"
        assert isinstance(
            ca_cert_object, OpenSSL.crypto.X509
        ), f"ca_cert_object is not an OpenSSL.crypto.X509type: {type(ca_cert_object)!r}"
        assert isinstance(
            sub_ca_cert_object, OpenSSL.crypto.X509
        ), "sub_ca_cert_object is not an OpenSSL.crypto.X509type: %r" % type(
            sub_ca_cert_object
        )
        assert isinstance(
            device_cert_object, OpenSSL.crypto.X509
        ), "device_cert_object is not an OpenSSL.crypto.X509type: %r" % type(
            device_cert_object
        )

        sigs = re.search(
            r"Signature\s+version:\s(\d+).+Signature:.+?([0-9A-F]+)",
            cmd_output,
            flags=re.DOTALL,
        )

        if not sigs:
            raise BootIntegrityValidator.MissingInfo(
                "The signature in the 'show platform sudi certificate' command output is not present"
            )

        sig_version = sigs.group(1)
        sig_signature = sigs.group(2)

        nonce_re = re.search(r"nonce\s+(\d+)", cmd_output)
        nonce = None
        if nonce_re:
            nonce = int(nonce_re.group(1))

        # Convert the signature from output in hex to bytes
        sig_signature_bytes = base64.b16decode(s=sig_signature)

        # data to be hashed
        header = (
            struct.pack(">QI", int(nonce), int(sig_version))
            if nonce
            else struct.pack(">I", int(sig_version))
        )
        ca_cert_der = OpenSSL.crypto.dump_certificate(
            type=OpenSSL.crypto.FILETYPE_ASN1, cert=ca_cert_object
        )
        cisco_sudi_der = OpenSSL.crypto.dump_certificate(
            type=OpenSSL.crypto.FILETYPE_ASN1, cert=sub_ca_cert_object
        )
        device_sudi_der = OpenSSL.crypto.dump_certificate(
            type=OpenSSL.crypto.FILETYPE_ASN1, cert=device_cert_object
        )
        data_to_be_hashed = header + ca_cert_der + cisco_sudi_der + device_sudi_der
        calculated_hash = SHA256.new(data_to_be_hashed)

        # validate calculated hash
        device_pkey_bin = OpenSSL.crypto.dump_publickey(
            type=OpenSSL.crypto.FILETYPE_ASN1, pkey=device_cert_object.get_pubkey()
        )

        device_rsa_key = RSA.importKey(device_pkey_bin)
        verifier = PKCS1_v1_5.new(device_rsa_key)
        if not verifier.verify(calculated_hash, sig_signature_bytes):
            raise BootIntegrityValidator.ValidationException(
                "Signature on show platform sudi output failed validation"
            )

    def _validate_show_platform_integrity_cmd_output(self, cmd_output):
        """
        Takes show platform integrity sign nonce xxx output and validates the following hashes against the values in the
        known_good_value dictionary
        -Boot 0 Hash
        -Boot Loader Hash
        -OS Hash


        :param cmd_output: string

        example input
        isr4321#show platform integrity sign nonce 1
        Platform: ISR4321/K9
        Boot 0 Version: F01023R12.1817bb4af2014-05-23
        Boot 0 Hash: B29EE97FA16911AE4058434EA7EC4464BD1341A57B17FB84550B2DDE2ABFDFD7
        Boot Loader Version: 16.2(2r)
        Boot Loader Hash: 5B02B6C175FEB8D097793.....38EC422FFB9BE53335772A9FED5A02D7
        OS Version: 16.03.01
        OS Hash: 4DDCC4A43F7913766370B....63181813AD810E32EC30936BEC1BA0DA26AE5AE2
        PCR0: 2D42A273E4C475B8D53A42A667599549ABE6028EC062EF15DEB15A12B41B0EA9
        PCR8: 6ADD719956CB838DE94AD850529EE77AF7A5222C05FE990E463D896498F37209
        Signature version: 1
        Signature:
        6E4D47F83D7AFF80...1ECB65206BAF2D08A210E2F8B
        isr4321#

        :return: Nothing.

        A ValueError will be raised if Version is not found in the kgv dictionary
        A ValidationError will be raised if validation fails
        A InvalidFormat if the kgv dict is invalid
        """

        self._logger.info(
            "Start validating the 'show platform integrity' command output"
        )
        assert isinstance(
            cmd_output, str
        ), f"cmd_output is not an string type: {type(cmd_output)!r}"

        platform_re = re.search(r"Platform:\s+(\S+)", cmd_output)
        if platform_re:
            cli_platform = platform_re.group(1)
            self._logger.debug("Platform is %s", cli_platform)
        else:
            self._logger.error("Unable to extract the Platform type from the output")
            raise BootIntegrityValidator.MissingInfo("Platform not found in cmd_output")

        def kgvs_for_dtype(dtype):
            if "bulkHash" not in self._kgv or not isinstance(
                self._kgv["bulkHash"], list
            ):
                raise BootIntegrityValidator.InvalidFormat(
                    "Structure of known_good_values provided in initializer is invalid"
                )
            for kgv in self._kgv["bulkHash"]:
                if kgv.get("dtype", "") == dtype:
                    yield kgv

        def validate_hash(cli_version, cli_hash, kgvs):
            """
            Looks for the cli_version in the versions and if present then checks the cli_hash against biv_hashes in entries

            :param cli_version: str
            :param cli_hash:  str
            :param kgvs:  list of dict
            :return: Nothing if validation successful

            :raises ValueError if cli_version not found in versions
            :raises ValidationError if cli_version found but none of biv_entries found
            :raises  BootIntegrityValidator.InvalidFormat, KeyError if versions is invalid format
            """

            assert isinstance(
                cli_version, str
            ), f"cli_version should be a string type:  {type(cli_version)!r}"
            assert isinstance(
                cli_hash, str
            ), f"cli_hash should be a string type:  {type(cli_hash)!r}"

            for kgv in kgvs:
                assert isinstance(kgv, dict), "all elements in versions should be dict"
                if kgv.get("biv_hash", "") == cli_hash:
                    return

            raise BootIntegrityValidator.ValidationException(
                f"version with biv_hash {cli_hash} not found in list of valid hashes"
            )

        def validate_all_os_hashes(os_hashes: typing.Tuple[str, str]):
            kgvs = kgvs_for_dtype(dtype="osimage")
            first_filename, first_hash = os_hashes[0]
            if re.search(r"^.*(?<!mono)-universalk9.*$", first_filename):
                # This is a mono image.  We can reduce the set down to a small set of pkgs
                parent_kgv = None
                for kgv in kgvs:
                    if kgv["filename"] == first_filename:
                        parent_kgv = kgv
                        break

                if not parent_kgv:
                    raise BootIntegrityValidator.ValidationException(
                        f"version with biv_hash {first_hash} not found in list of valid hashes"
                    )

                pkg_kgvs = {
                    kgv["filename"]: kgv.get("biv_hash") for kgv in parent_kgv["pkg"]
                }
            else:
                # Have to get ALL osimage and ALL sub packages into a single dictionary
                pkg_kgvs = {}
                for kgv in kgvs:
                    pkg_kgvs[kgv["filename"]] = kgv.get("biv_hash")
                    for pkg_kgv in kgv.get("pkg", []):
                        pkg_kgvs[pkg_kgv["filename"]] = pkg_kgv.get("biv_hash")

            for given_pkg_filename, given_pkg_hash in os_hashes[1:]:
                if given_pkg_filename not in pkg_kgvs:
                    raise BootIntegrityValidator.ValidationException(
                        f"package {given_pkg_filename} not found in list of valid hashes"
                    )
                if pkg_kgvs[given_pkg_filename] != given_pkg_hash:
                    raise BootIntegrityValidator.ValidationException(
                        f"version {given_pkg_filename} with biv_hash {given_pkg_hash} doesn't match Known good value of {pkg_kgvs[given_pkg_filename]}"
                    )

        # Some of the biv_hashes are truncated
        acceptable_biv_hash_lengths = (64, 128)

        if "Signature" in cmd_output:
            if "device" in self._cert_obj:
                self._logger.info(
                    "'show platform integrity' command has signature.  Attempt to validate"
                )
                try:
                    self._validate_show_platform_integrity_cmd_output_signature(
                        cmd_output=cmd_output,
                        device_cert_object=self._cert_obj["device"],
                    )
                except BootIntegrityValidator.ValidationException as e:
                    self._logger.error("Validation failed", exc_info=True)
                    raise

                self._logger.info("Validation succeeded")
            else:
                self._logger.error(
                    "Can't validate the 'show platform integrity' command signature as the 'show platform sudi certificate' command wasn't provided"
                )
                raise BootIntegrityValidator.MissingInfo(
                    "Signature can't be validated because the SUDI certificates haven't been provided"
                )

        # Got the KGV for this platform
        # Check the boot0Version first
        boot_0_version_re = re.search(
            pattern=r"Boot 0 Version:[^\S\n]*(.*)\n", string=cmd_output
        )
        boot_0_hash_re = re.search(
            pattern=r"Boot 0 Hash:[^\S\n]*(.*)\n", string=cmd_output
        )

        self._logger.info("Attempting to extract Boot 0 Version and Hash")
        if boot_0_hash_re is None or boot_0_version_re is None:
            raise BootIntegrityValidator.MissingInfo(
                "'Boot 0 Version' or 'Boot 0 Hash' not found in cmd_output"
            )
        if not boot_0_version_re.group(1):
            raise BootIntegrityValidator.MissingInfo(
                "Boot 0 Version not present in cmd_output"
            )
        if not boot_0_hash_re.group(1):
            raise BootIntegrityValidator.MissingInfo(
                "Boot 0 Hash not present in cmd_output"
            )
        if len(boot_0_hash_re.group(1)) not in acceptable_biv_hash_lengths:
            raise BootIntegrityValidator.MissingInfo(
                "Boot 0 Hash '{hash}' is of len {length} should be one of {sizes}".format(
                    hash=boot_0_hash_re.group(1),
                    length=len(boot_0_hash_re.group(1)),
                    sizes=acceptable_biv_hash_lengths,
                )
            )

        # Validate boot0Versions
        validate_hash(
            cli_version=boot_0_version_re.group(1),
            cli_hash=boot_0_hash_re.group(1),
            kgvs=kgvs_for_dtype(dtype="boot0"),
        )
        self._logger.info("Boot 0 validation successful")

        # Check the bootLoader second
        boot_loader_version_re = re.search(
            pattern=r"Boot Loader Version:[^\S\n]*(.*)\n", string=cmd_output
        )
        boot_loader_hash_re = re.search(
            pattern=r"Boot Loader Hash:[^\S\n]*(.*)\n", string=cmd_output
        )

        self._logger.info("Attempting to extract Boot Loader Version and Hash")
        if boot_loader_hash_re is None or boot_loader_version_re is None:
            raise BootIntegrityValidator.MissingInfo(
                "'Boot Loader Version' or 'Boot Loader Hash' not found in cmd_output"
            )
        if not boot_loader_version_re.group(1):
            raise BootIntegrityValidator.MissingInfo(
                "Boot Loader Version not present in cmd_output"
            )
        if not boot_loader_hash_re.group(1):
            raise BootIntegrityValidator.MissingInfo(
                "Boot Loader Hash not present in cmd_output"
            )
        if len(boot_loader_hash_re.group(1)) not in acceptable_biv_hash_lengths:
            raise BootIntegrityValidator.MissingInfo(
                "Boot Loader Hash '{hash}' is of len {length} should be one of {sizes}".format(
                    hash=boot_loader_hash_re.group(1),
                    length=len(boot_loader_hash_re.group(1)),
                    sizes=acceptable_biv_hash_lengths,
                )
            )

        validate_hash(
            cli_version=boot_loader_version_re.group(1),
            cli_hash=boot_loader_hash_re.group(1),
            kgvs=kgvs_for_dtype(dtype="blr"),
        )
        self._logger.info("Boot Loader validation successful")

        # Check the OS third but there might be 1 or many hashes
        self._logger.info("Attempt to extract OS Version and Hash")
        os_version_re = re.search(
            pattern=r"OS Version:[^\S\n]*(.*)\n", string=cmd_output
        )
        if not os_version_re or not os_version_re.group(1):
            raise BootIntegrityValidator.MissingInfo(
                "'OS Version' not found in cmd_output"
            )

        try:
            os_hashes = BootIntegrityValidator._extract_os_hashes(cmd_output=cmd_output)
        except ValueError:
            raise BootIntegrityValidator.MissingInfo(
                "'OS Hash' or 'OS Hashes' not found in cmd_output"
            )

        for filename, hash in os_hashes:
            if len(hash) not in acceptable_biv_hash_lengths:
                raise BootIntegrityValidator.MissingInfo(
                    f"OS Hash '{filename}' '{hash}' is of len {len(hash)} should be one of {acceptable_biv_hash_lengths}"
                )

        if len(os_hashes) == 1:
            # Single OS hash
            validate_hash(
                cli_version=os_version_re.group(1),
                cli_hash=os_hashes[0][1],
                kgvs=kgvs_for_dtype(dtype="osimage"),
            )
            self._logger.info("OS validation successful")
            # Successfully validated
        else:
            # Multi hash to validate
            validate_all_os_hashes(os_hashes=os_hashes)

        self._logger.info(
            "Finished validating the 'show platform integrity' command output"
        )

    @staticmethod
    def _extract_os_hashes(cmd_output: str) -> typing.Tuple[str, str]:
        """
        The OS hash output could be a single hash OR it could be a list of hashes

        # Example single hash
        OS Version: 16.03.01
        OS Hash: 4DDCC4A43F791......98963181813AD810E32EC30936BEC1BA0DA26AE5AE2
        PCR0: 2D42A273E4C475B8D53A42A667599549ABE6028EC062EF15DEB15A12B41B0EA9

        # Example multiple hashes
        OS Version: 17.04.01a
        OS Hashes:
        isr4400-universalk9.17.04.01a.SPA.bin: A5A505D87DD43534A7B3F30D7158D4AACE7B787105265288A4C62E44EFAFD9246C4A644104BE70C648492AEC4F415EBD988B0DE64ED7210058835E042AC1393F
        isr4400-mono-universalk9.17.04.01a.SPA.pkg: E27B520E9373613AC5F8FEEFBC7FF42B426EA3F87367D8F293D0122B93CFB01D19F33434D3B0F8906D8FB6C978F1CC4A2894C864795E35EFB325ED4C5EC8D8BD
        isr4400-firmware_nim_shdsl.17.04.01a.SPA.pkg: F4BCFA451A95C9EE7F2B8585C23FAD57E90CD01E72C03D3711EE821255A03E64894D64A2AFD2580FF64B65806709D371410F5C08C39732706EE172183AEDDF33
        ....
        """

        single_os_hash_re = re.search(
            pattern=r"OS Hash:[^\S\n]*(.*)\n", string=cmd_output
        )
        if single_os_hash_re:
            return (("single_hash", single_os_hash_re.group(1)),)

        multi_os_hash_re = re.search(
            pattern=r"OS Hashes:\s*\n((?:.|\n)*)PCR0:", string=cmd_output
        )
        if multi_os_hash_re:
            # Check for all hashes
            # For Example
            # OS Version: 17.04.01a
            # OS Hashes:
            # isr4400-universalk9.17.04.01a.SPA.bin: A5A505D87DD43534A7B3F30D7158D4AACE7B787105265288A4C62E44EFAFD9246C4A644104BE70C648492AEC4F415EBD988B0DE64ED7210058835E042AC1393F
            # isr4400-mono-universalk9.17.04.01a.SPA.pkg: E27B520E9373613AC5F8FEEFBC7FF42B426EA3F87367D8F293D0122B93CFB01D19F33434D3B0F8906D8FB6C978F1CC4A2894C864795E35EFB325ED4C5EC8D8BD
            # isr4400-firmware_nim_shdsl.17.04.01a.SPA.pkg: F4BCFA451A95C9EE7F2B8585C23FAD57E90CD01E72C03D3711EE821255A03E64894D64A2AFD2580FF64B65806709D371410F5C08C39732706EE172183AEDDF33
            os_hashes = []
            os_hashes_text_re = re.search(
                pattern=r"OS Hashes:\s*\n((?:.|\n)*)PCR0:", string=cmd_output
            )
            os_hashes_text = os_hashes_text_re.group(1).splitlines()
            for hash_line in os_hashes_text:
                hash_re = re.search(
                    pattern=r"^(?P<filename>\S+)\:\s*(?P<hash>[0-9A-F]+)\s*$",
                    string=hash_line,
                )
                if hash_re:
                    os_hashes.append(
                        (hash_re.groupdict()["filename"], hash_re.groupdict()["hash"])
                    )
            return tuple(os_hashes)

        raise ValueError("Unable to find the OS hashes in cmd_output")

    @staticmethod
    def _validate_show_platform_integrity_cmd_output_signature(
        cmd_output, device_cert_object
    ):
        """

        :param cmd_output: str of output

        example input

        isr4321#show platform integrity sign nonce 1
        Platform: ISR4321/K9
        Boot 0 Version: F01023R12.1817bb4af2014-05-23
        Boot 0 Hash: B29EE97FA16911AE4058434EA7EC4464BD1341A57B17FB84550B2DDE2ABFDFD7
        Boot Loader Version: 16.2(2r)
        Boot Loader Hash: 5B02B6C175FEB8D097.....FB9BE53335772A9FED5A02D7
        OS Version: 16.03.01
        OS Hash: 4DDCC4A43F791......98963181813AD810E32EC30936BEC1BA0DA26AE5AE2
        PCR0: 2D42A273E4C475B8D53A42A667599549ABE6028EC062EF15DEB15A12B41B0EA9
        PCR8: 6ADD719956CB838DE94AD850529EE77AF7A5222C05FE990E463D896498F37209
        Signature version: 1
        Signature:
        6E4D47F83D7AFF804CD4B6D002........31D330CBAF2D08A210E2F8B
        isr4321#

        :param device_cert_object: Openssl.crypto.x509
        :return:
        """

        assert isinstance(
            cmd_output, str
        ), f"cmd_output is not an string type: {type(cmd_output)!r}"
        assert isinstance(
            device_cert_object, OpenSSL.crypto.X509
        ), "device_cert_object is not an OpenSSL.crypto.X509type: %r" % type(
            device_cert_object
        )

        sigs = re.search(
            r"Signature\s+version:\s(\d+).+Signature:.+?([0-9A-F]+)",
            cmd_output,
            flags=re.DOTALL,
        )
        if sigs is None:
            raise BootIntegrityValidator.MissingInfo(
                "Signature not present in cmd_output"
            )
        sig_version = sigs.group(1)
        sig_signature = sigs.group(2)

        nonce_re = re.search(r"nonce\s+(\d+)", cmd_output)
        nonce = None
        if nonce_re:
            nonce = int(nonce_re.group(1))

        # Convert the signature from output in hex to bytes
        sig_signature_bytes = base64.b16decode(s=sig_signature)

        pcr0_re = re.search(r"PCR0:\s+?([0-9A-F]+)", cmd_output, flags=re.DOTALL)
        pcr0_received_text = pcr0_re.group(1)
        pcr8_re = re.search(r"PCR8:\s+?([0-9A-F]+)", cmd_output, flags=re.DOTALL)
        pcr8_received_text = pcr8_re.group(1)

        # data to be hashed
        header = (
            struct.pack(">QI", int(nonce), int(sig_version))
            if nonce
            else struct.pack(">I", int(sig_version))
        )
        pcr0_received_bytes = base64.b16decode(pcr0_received_text)
        pcr8_received_bytes = base64.b16decode(pcr8_received_text)
        data_to_be_hashed = header + pcr0_received_bytes + pcr8_received_bytes
        calculated_hash = SHA256.new(data_to_be_hashed)

        # validate calculated hash
        device_pkey_bin = OpenSSL.crypto.dump_publickey(
            type=OpenSSL.crypto.FILETYPE_ASN1, pkey=device_cert_object.get_pubkey()
        )

        device_rsa_key = RSA.importKey(device_pkey_bin)
        verifier = PKCS1_v1_5.new(device_rsa_key)
        if not verifier.verify(calculated_hash, sig_signature_bytes):
            raise BootIntegrityValidator.ValidationException(
                "Signature on show platform integrity output failed validation"
            )

        # Signature over the reported PCR0 and PRCR8 passed.  Now they need to be computed and compared against
        # the received values.
        # PCR0 is extended using 256-bits of 0 as the initial PCR0 and the SHA256 hash of Boot 0 Hash measurement.
        # The PRC0 is then extended further using the SHA256 hash of the Boot Loader measurement
        # The PCR8 is extended using 256-bits of 0 as the initial PRC8 and the SHA256 hash of OS Hash measurement.

        # PCR0 Calculation
        boot_0_hash_re = re.search(pattern=r"Boot 0 Hash:\s+(\S+)", string=cmd_output)
        if not boot_0_hash_re:
            raise BootIntegrityValidator.InvalidFormat(
                "Boot 0 Hash not found in cmd_output"
            )
        boot_0_hash_bytes = base64.b16decode(boot_0_hash_re.group(1))
        b0_measurement_hash = SHA256.new(boot_0_hash_bytes).digest()
        init = b"\x00" * 32
        pcr0_computed = SHA256.new(init + b0_measurement_hash).digest()
        # Now repeat for the Boot Loader measurement
        boot_loader_hash_re = re.search(
            pattern=r"Boot Loader Hash:\s+(\S+)", string=cmd_output
        )
        if not boot_loader_hash_re:
            raise BootIntegrityValidator.InvalidFormat(
                "Boot Loader Hash not found in cmd_output"
            )
        boot_loader_hash_bytes = base64.b16decode(boot_loader_hash_re.group(1))
        bl_measurement_hash = SHA256.new(boot_loader_hash_bytes).digest()
        pcr0_computed = SHA256.new(pcr0_computed + bl_measurement_hash).digest()
        pcr0_computed_text = base64.b16encode(pcr0_computed).decode()

        if pcr0_computed_text != pcr0_received_text:
            raise BootIntegrityValidator.ValidationException(
                "The received PCR0 was signed correctly but doesn't match the computed PRC0 using the given measurements."
            )

        # PCR8 Calculation
        os_hashes = BootIntegrityValidator._extract_os_hashes(cmd_output=cmd_output)
        pcr8_computed = b"\x00" * 32
        for _, hash in os_hashes:
            os_hash_bytes = SHA256.new(base64.b16decode(hash)).digest()
            pcr8_computed = SHA256.new(pcr8_computed + os_hash_bytes).digest()

        pcr8_computed_text = base64.b16encode(pcr8_computed).decode()
        if pcr8_computed_text != pcr8_received_text:
            raise BootIntegrityValidator.ValidationException(
                "The received PCR8 was signed correctly but doesn't match the computed PRC8 using the given measurements."
            )

    def validate_v2_cli(
        self,
        show_system_integrity_trust_chain_cmd_output: str,
        show_system_integrity_compliance_cmd_output: str,
        show_system_integrity_measurement_cmd_output: str,
    ) -> None:
        """
        Takes the cli output of
            - `show system integrity all trust_chain nonce <INT>`
            - `show system integrity all compliance nonce <INT>`
            - `show system integrity all measurement nonce <INT>`

        Does the following:
            - Transforms each cli output in a valid JSON data structure that matches the YANG model
            - Then calls the `validate_v2_json` function
            - Validates the Certificate Chain for the SUDI certificate
            - Validates each of the CLI outputs against the signatures given
            - Validates the measurements against the Known-Good-Values (KGV)

        """

        self._logger.info("Starting BIV v2 validation - CLI")
        if not isinstance(show_system_integrity_trust_chain_cmd_output, str):
            raise TypeError(
                f"'show_system_integrity_trust_chain_cmd_output' should be a str type but is {type(show_system_integrity_trust_chain_cmd_output)}"
            )
        if not isinstance(show_system_integrity_compliance_cmd_output, str):
            raise TypeError(
                f"'show_system_integrity_compliance_cmd_output' should be a str type but is {type(show_system_integrity_compliance_cmd_output)}"
            )
        if not isinstance(show_system_integrity_measurement_cmd_output, str):
            raise TypeError(
                f"show_system_integrity_measurement_cmd_output should be a str type but is {type(show_system_integrity_measurement_cmd_output)}"
            )

        from . import yang

        # Convert the cli into the json data instance
        trust_chain_json = yang.parse_show_system_integrity_trust_chain_nonce(
            cmd_output=show_system_integrity_trust_chain_cmd_output
        )
        compliance_json = yang.parse_show_system_integrity_compliance_nonce(
            cmd_output=show_system_integrity_compliance_cmd_output
        )
        measurement_json = yang.parse_show_system_integrity_measurement_nonce(
            cmd_output=show_system_integrity_measurement_cmd_output
        )

        # Now the data has been normalized to a json data instance of the YANG model
        # Call the validate function
        self.validate_v2_json(
            show_system_integrity_trust_chain_json=trust_chain_json,
            show_system_integrity_compliance_json=compliance_json,
            show_system_integrity_measurement_json=measurement_json,
        )

    def validate_v2_xml(
        self,
        show_system_integrity_trust_chain_xml: str,
        show_system_integrity_compliance_xml: str,
        show_system_integrity_measurement_xml: str,
    ) -> None:
        """
        Takes the xml data model for the Cisco-IOS-XE-system-integrity-oper:system-integrity-ios-xe-oper yang models

        Does the following:
            - Validates the data instances against the yang model
            - Transforms the xml data instances int json data instances
            - Calls the `validate_v2_json` method
        """
        self._logger.info("Starting BIV v2 validation - XML")
        if not isinstance(show_system_integrity_trust_chain_xml, str):
            raise TypeError(
                f"'show_system_integrity_trust_chain_xml' should be a str type but is {type(show_system_integrity_trust_chain_xml)}"
            )
        if not isinstance(show_system_integrity_compliance_xml, str):
            raise TypeError(
                f"'show_system_integrity_compliance_xml' should be a str type but is {type(show_system_integrity_compliance_xml)}"
            )
        if not isinstance(show_system_integrity_measurement_xml, str):
            raise TypeError(
                f"show_system_integrity_measurement_xml should be a str type but is {type(show_system_integrity_measurement_xml)}"
            )

        # Very basic sanity check that the passed in xml corresponds to the expect data model

        if "<trust-chain>" not in show_system_integrity_trust_chain_xml:
            raise ValueError(
                "Unexpected content found in 'show_system_integrity_trust_chain_xml'"
            )
        if "<compliance>" not in show_system_integrity_compliance_xml:
            raise ValueError(
                "Unexpected content found in 'show_system_integrity_compliance_xml'"
            )
        if "<measurement>" not in show_system_integrity_measurement_xml:
            raise ValueError(
                "Unexpected content found in 'show_system_integrity_measurement_xml'"
            )

        from . import yang

        trust_chain_json = yang.validate_xml_measurement(
            xml_measurement=show_system_integrity_trust_chain_xml
        )
        compliance_json = yang.validate_xml_measurement(
            xml_measurement=show_system_integrity_compliance_xml
        )
        measurement_json = yang.validate_xml_measurement(
            xml_measurement=show_system_integrity_measurement_xml
        )

        self.validate_v2_json(
            show_system_integrity_trust_chain_json=trust_chain_json,
            show_system_integrity_compliance_json=compliance_json,
            show_system_integrity_measurement_json=measurement_json,
        )

    def _validate_v2_trust_chain(self, trust_chain: dict) -> dict:
        """
        Validate the trust chain against the Cisco CA and validate the signature
        using the supplied SUDI certs.

        Returns a dictionary of the SUDI certs accessible keyed on Location

        :param: trust_chain - json data model of trust chains
        :returns: dict - key is a `Location`, value is a `OpenSSL.x509`

        """
        self._logger.info("Starting BIV v2 validation - Trust Chain Validation")
        crca2048 = self._cert_obj["crca2048"]
        act2sudica = self._cert_obj["ACT2SUDICA"]
        crca2099 = self._cert_obj["crca2099"]
        hasudi = self._cert_obj["hasudi"]

        def same_cert(a, b):
            a_bytes = OpenSSL.crypto.dump_certificate(
                type=OpenSSL.crypto.FILETYPE_ASN1, cert=a
            )
            b_bytes = OpenSSL.crypto.dump_certificate(
                type=OpenSSL.crypto.FILETYPE_ASN1, cert=b
            )
            return a_bytes == b_bytes

        sudi_certs = {}
        for location in trust_chain[
            "Cisco-IOS-XE-system-integrity-oper:system-integrity-oper-data"
        ]["location"]:
            location_dict = copy.deepcopy(location)
            del location_dict["integrity"]
            trust_chain = location["integrity"][0]["trust-chain"]
            nonce = int(location["integrity"][0]["nonce"])
            loc = BootIntegrityValidator.Location(**location_dict)
            cert_chain = trust_chain["trust-chain"]

            # Compare CA against known good CA
            ca_cert_text = cert_chain[0]["value"]
            ca_cert_bytes = base64.b64decode(ca_cert_text)
            ca_cert_obj = OpenSSL.crypto.load_certificate(
                type=OpenSSL.crypto.FILETYPE_ASN1, buffer=ca_cert_bytes
            )
            if not any([same_cert(x, ca_cert_obj) for x in [crca2048, crca2099]]):
                self._logger.error(
                    "Cisco Root CA in cmd_output doesn't match a known good Cisco Root CA"
                )
                raise BootIntegrityValidator.ValidationException(
                    "Cisco Root CA in cmd_output doesn't match known good Cisco Root CA"
                )

            # Compare Sub-CA against known good Sub-CA
            cisco_sudi_ca_text = cert_chain[1]["value"]
            cisco_sudi_ca_bytes = base64.b64decode(cisco_sudi_ca_text)
            cisco_sudi_obj = OpenSSL.crypto.load_certificate(
                type=OpenSSL.crypto.FILETYPE_ASN1, buffer=cisco_sudi_ca_bytes
            )
            if not any([same_cert(x, cisco_sudi_obj)] for x in [act2sudica, hasudi]):
                self._logger.error(
                    "Cisco SUDI Sub-CA in cmd_output doesn't match known good Cisco SUDI CA"
                )
                raise BootIntegrityValidator.ValidationException(
                    "Cisco SUDI Sub-CA in cmd_output doesn't match known good Cisco SUDI CA"
                )

            # Device sudi cert
            device_sudi_text = cert_chain[2]["value"]
            device_sudi_bytes = base64.b64decode(device_sudi_text)
            device_sudi_obj = OpenSSL.crypto.load_certificate(
                type=OpenSSL.crypto.FILETYPE_ASN1, buffer=device_sudi_bytes
            )
            # validate Device ID Certificate
            try:
                self._logger.info("Validating device certificate against Cisco CAs")
                store_ctx = OpenSSL.crypto.X509StoreContext(
                    store=self._trusted_store, certificate=device_sudi_obj
                )
                store_ctx.verify_certificate()
                # SUDI certificate is validate
                sudi_certs[loc] = {"nonce": nonce, "cert_obj": device_sudi_obj}
            except OpenSSL.crypto.X509StoreContextError:
                self._logger.error(
                    "Device ID Certificate failed validation against Cisco CA Roots"
                )
                raise BootIntegrityValidator.ValidationException(
                    "Device ID Certificate failed validation against Cisco CA Roots"
                )

            # The SUDI certificate is valid, now we need to validate the signature over the three certs

            signature = trust_chain["signature"]
            header = struct.pack(">QI", nonce, signature["version"])
            data_to_be_hashed = (
                header + ca_cert_bytes + cisco_sudi_ca_bytes + device_sudi_bytes
            )
            calculated_hash = SHA256.new(data=data_to_be_hashed)

            # Validate calculated hash
            device_pkey_bin = OpenSSL.crypto.dump_publickey(
                type=OpenSSL.crypto.FILETYPE_ASN1, pkey=device_sudi_obj.get_pubkey()
            )
            device_rsa_key = RSA.importKey(device_pkey_bin)
            verifier = PKCS1_v1_5.new(device_rsa_key)

            signature_bytes = base64.b16decode(signature["signature"])
            if not verifier.verify(calculated_hash, signature_bytes):
                raise BootIntegrityValidator.ValidationException(
                    "Signature on show system integrity all trust-chain failed validation"
                )
            sudi_certs[loc] = device_sudi_obj

        return sudi_certs

    def _validate_v2_compliance(
        self,
        compliance: dict,
        sudi_certs: typing.Mapping[Location, OpenSSL.crypto.X509],
    ) -> dict:

        compliance_info = {}
        for location in compliance[
            "Cisco-IOS-XE-system-integrity-oper:system-integrity-oper-data"
        ]["location"]:
            location_dict = copy.deepcopy(location)
            del location_dict["integrity"]
            loc = BootIntegrityValidator.Location(**location_dict)
            compliance = location["integrity"][0]["compliance"]
            signature = compliance["signature"]

            nonce = int(location["integrity"][0]["nonce"])
            header = struct.pack(">QI", nonce, signature["version"])
            compliance_bytes = compliance["category"].encode()
            data_to_be_hashed = header + compliance_bytes
            calculated_hash = SHA256.new(data=data_to_be_hashed)

            try:
                device_sudi_obj = sudi_certs[loc]
            except KeyError:
                raise BootIntegrityValidator.MissingInfo(
                    f"Compliance information can't be validated because the trust-chain for the following location is missing {loc}"
                )
            device_pkey_bin = OpenSSL.crypto.dump_publickey(
                type=OpenSSL.crypto.FILETYPE_ASN1, pkey=device_sudi_obj.get_pubkey()
            )
            device_rsa_key = RSA.importKey(device_pkey_bin)
            verifier = PKCS1_v1_5.new(device_rsa_key)
            signature_bytes = base64.b16decode(signature["signature"])
            if not verifier.verify(calculated_hash, signature_bytes):
                raise BootIntegrityValidator.ValidationException(
                    "Signature on show system integrity all compliance failed validation"
                )
            compliance_info[loc] = json.loads(compliance["category"])

        return compliance_info

    def _validate_v2_measurement(
        self,
        measurements: dict,
        compliance_info: dict,
        sudi_certs: typing.Mapping[Location, OpenSSL.crypto.X509],
    ) -> None:
        self._logger.info("Start v2 measure validation")

        def kgvs_for_dtype(dtype):
            if "bulkHash" not in self._kgv or not isinstance(
                self._kgv["bulkHash"], list
            ):
                raise BootIntegrityValidator.InvalidFormat(
                    "Structure of known_good_values provided in initializer is invalid"
                )
            for kgv in self._kgv["bulkHash"]:
                if kgv.get("dtype", "") == dtype:
                    yield kgv

        def validate_hash(version, hash_value, kgvs):
            """
            Looks for the cli_version in the versions and if present then checks the cli_hash against biv_hashes in entries

            :param cli_version: str
            :param cli_hash:  str
            :param kgvs:  list of dict
            :return: Nothing if validation successful

            :raises ValueError if cli_version not found in versions
            :raises ValidationError if cli_version found but none of biv_entries found
            :raises  BootIntegrityValidator.InvalidFormat, KeyError if versions is invalid format
            """

            assert isinstance(
                version, str
            ), f"cli_version should be a string type:  {type(version)!r}"
            assert isinstance(
                hash_value, str
            ), f"cli_hash should be a string type:  {type(hash_value)!r}"

            for kgv in kgvs:
                assert isinstance(kgv, dict), "all elements in versions should be dict"
                if kgv.get("biv_hash", "") == hash_value:
                    return

            raise BootIntegrityValidator.ValidationException(
                f"version with biv_hash {hash_value} not found in list of valid hashes"
            )

        def validate_all_os_hashes(os_hashes: typing.List[typing.Tuple[str, str]]):
            kgvs = kgvs_for_dtype(dtype="osimage")
            first_filename, first_hash = os_hashes[0]
            if re.search(r"^.*(?<!mono)-universalk9.*$", first_filename):
                # This is a mono image.  We can reduce the set down to a small set of pkgs
                parent_kgv = None
                for kgv in kgvs:
                    if kgv["filename"] == first_filename:
                        parent_kgv = kgv
                        break

                if not parent_kgv:
                    raise BootIntegrityValidator.ValidationException(
                        f"version with biv_hash {first_hash} not found in list of valid hashes"
                    )

                pkg_kgvs = {
                    kgv["filename"]: kgv.get("biv_hash") for kgv in parent_kgv["pkg"]
                }
            else:
                # Have to get ALL osimage and ALL sub packages into a single dictionary
                pkg_kgvs = {}
                for kgv in kgvs:
                    pkg_kgvs[kgv["filename"]] = kgv.get("biv_hash")
                    for pkg_kgv in kgv.get("pkg", []):
                        pkg_kgvs[pkg_kgv["filename"]] = pkg_kgv.get("biv_hash")

            for given_pkg_filename, given_pkg_hash in os_hashes:
                if given_pkg_filename not in pkg_kgvs:
                    raise BootIntegrityValidator.ValidationException(
                        f"package {given_pkg_filename} not found in list of valid hashes"
                    )
                if pkg_kgvs[given_pkg_filename] != given_pkg_hash:
                    raise BootIntegrityValidator.ValidationException(
                        f"version {given_pkg_filename} with biv_hash {given_pkg_hash} doesn't match Known good value of {pkg_kgvs[given_pkg_filename]}"
                    )

        for location in measurements[
            "Cisco-IOS-XE-system-integrity-oper:system-integrity-oper-data"
        ]["location"]:
            self._logger.debug(f"Working on {location}")
            location_dict = copy.deepcopy(location)
            del location_dict["integrity"]
            loc = BootIntegrityValidator.Location(**location_dict)
            measurement = location["integrity"][0]["measurement"]
            signature = measurement["signature"]

            nonce = int(location["integrity"][0]["nonce"])
            header = struct.pack(">QI", nonce, signature["version"])
            # Validate the Signature over PCR0 and PCR8 first

            pcr0_hex = None
            pcr8_hex = None
            for pcr in measurement["register"]:
                if pcr["index"] == 0:
                    pcr0_hex = pcr["pcr-content"]
                elif pcr["index"] == 8:
                    pcr8_hex = pcr["pcr-content"]

            assert pcr0_hex
            assert pcr8_hex
            data_to_be_hashed = (
                header + base64.b16decode(pcr0_hex) + base64.b16decode(pcr8_hex)
            )
            calculated_hash = SHA256.new(data_to_be_hashed)

            try:
                device_sudi_obj = sudi_certs[loc]
            except KeyError:
                raise BootIntegrityValidator.MissingInfo(
                    f"Measurement information can't be validated because the trust-chain for the following location is missing {loc}"
                )
            device_pkey_bin = OpenSSL.crypto.dump_publickey(
                type=OpenSSL.crypto.FILETYPE_ASN1, pkey=device_sudi_obj.get_pubkey()
            )
            device_rsa_key = RSA.importKey(device_pkey_bin)
            verifier = PKCS1_v1_5.new(device_rsa_key)
            signature_bytes = base64.b16decode(signature["signature"])
            if not verifier.verify(calculated_hash, signature_bytes):
                raise BootIntegrityValidator.ValidationException(
                    f"Signature on show system integrity all compliance failed validation for {loc}"
                )

            # Signature Validation of PCR registers successful

            # Signature over the reported PCR0 and PRCR8 passed.  Now they need to be computed and compared against
            # the received values.
            # PCR0 is extended using 256-bits of 0 as the initial PCR0 and the SHA256 hash of Boot 0 Hash measurement.
            # The PRC0 is then extended further using the SHA256 hash of the Boot Loader measurement
            # The PCR8 is extended using 256-bits of 0 as the initial PRC8 and the SHA256 hash of OS Hash measurement.

            # PCR0 Calculation
            hash_output = b"\x00" * 32
            for stage in sorted(measurement["boot-loader"], key=lambda s: s["stage"]):
                stage_hash_bytes = SHA256.new(base64.b16decode(stage["hash"])).digest()
                hash_output = SHA256.new(hash_output + stage_hash_bytes).digest()
            pcr0_computed_text = base64.b16encode(hash_output).decode()

            if pcr0_computed_text != pcr0_hex:
                raise BootIntegrityValidator.ValidationException(
                    f"The received PCR0 was signed correctly but doesn't match the computed PRC0 using the given measurements for {loc}"
                )

            # PCR0 Validation Successful
            # PCR8 Calculation
            hash_output = b"\x00" * 32
            for index in sorted(
                measurement["operating-system"]["package-integrity"],
                key=lambda i: i["index"],
            ):
                os_hash_bytes = SHA256.new(base64.b16decode(index["hash"])).digest()
                hash_output = SHA256.new(hash_output + os_hash_bytes).digest()
            pcr8_computed_text = base64.b16encode(hash_output).decode()

            if pcr8_computed_text != pcr8_hex:
                raise BootIntegrityValidator.ValidationException(
                    f"The received PCR8 was signed correctly but doesn't match the computed PRC8 using the given measurements for {loc}"
                )
            # PCR8 Validation Successful

            # Now we have confirmed that the output was generated from boxes running the hashes
            # that are included in the output.  Now we have to validate that the hashes are found
            # within the KGV

            self._logger.debug(
                f"Succesfully validated the cryptographic output provided for {loc}"
            )

            # First stage of boot hashes = boot0
            # Second and further stages of boot hashes = bootLoader
            # OS hashes = osImageVersions

            try:
                compliance_loc_info = compliance_info[loc]
            except KeyError:
                raise BootIntegrityValidator.MissingInfo(
                    f"Measurement information can't be validated because the compliance info for the following location is missing {loc}"
                )

            biv_len = compliance_loc_info["capabilities"]["bivlen"]
            (boot0_measure, *bootloader_measures) = sorted(
                measurement["boot-loader"], key=lambda s: s["stage"]
            )
            # Validate boot0
            validate_hash(
                version=boot0_measure["version"],
                hash_value=boot0_measure["hash"],
                kgvs=kgvs_for_dtype(dtype="boot0"),
            )

            # Validate remaining bootloaders
            for bootloader_measure in bootloader_measures:
                validate_hash(
                    version=bootloader_measure["version"],
                    hash_value=bootloader_measure["hash"],
                    kgvs=kgvs_for_dtype(dtype="blr"),
                )

            os_measures = sorted(
                measurement["operating-system"]["package-integrity"],
                key=lambda s: s["index"],
            )
            if len(os_measures) == 1:
                # Single OS hash
                validate_hash(
                    version=os_measures[0]["version"],
                    hash_value=os_measures[0]["hash"],
                    kgvs=kgvs_for_dtype(dtype="osimage"),
                )
            else:
                validate_all_os_hashes(
                    os_hashes=([(h["name"], h["hash"]) for h in os_measures])
                )

            # Location successfully validated

        # Whole measurement successfully validated

    def validate_v2_json(
        self,
        show_system_integrity_trust_chain_json: dict,
        show_system_integrity_compliance_json: dict,
        show_system_integrity_measurement_json: dict,
    ) -> None:
        """
        Takes the json data model for the Cisco-IOS-XE-system-integrity-oper:system-integrity-ios-xe-oper yang models

        Does the following:
            - Validates the
            - Validates the Certificate Chain for the SUDI certificate
            - Validates each of the CLI outputs against the signatures given
            - Validates the measurements against the Known-Good-Values (KGV)

        """
        self._logger.info("Starting BIV v2 validation - JSON")
        if not isinstance(show_system_integrity_trust_chain_json, dict):
            raise TypeError(
                f"'show_system_integrity_trust_chain_json' was a '{type(show_system_integrity_trust_chain_json)}' expected a 'dict'"
            )
        if not isinstance(show_system_integrity_compliance_json, dict):
            raise TypeError(
                f"'show_system_integrity_compliance_json' was a '{type(show_system_integrity_compliance_json)}' expected a 'dict'"
            )
        if not isinstance(show_system_integrity_measurement_json, dict):
            raise TypeError(
                f"'show_system_integrity_measurement_json' was a '{type(show_system_integrity_measurement_json)}' expected a 'dict'"
            )

        # Very basic sanity check that the passed in json corresponds to the expect data model

        if '"trust-chain"' not in json.dumps(show_system_integrity_trust_chain_json):
            raise ValueError(
                "Unexpected content found in 'show_system_integrity_trust_chain_json'"
            )
        if '"compliance"' not in json.dumps(show_system_integrity_compliance_json):
            raise ValueError(
                "Unexpected content found in 'show_system_integrity_compliance_json'"
            )
        if '"measurement"' not in json.dumps(show_system_integrity_measurement_json):
            raise ValueError(
                "Unexpected content found in 'show_system_integrity_measurement_json'"
            )

        # validate the json objects against the data model
        from . import yang

        yang.validate_json_measurement(
            json_measurement=show_system_integrity_trust_chain_json
        )
        yang.validate_json_measurement(
            json_measurement=show_system_integrity_compliance_json
        )
        yang.validate_json_measurement(
            json_measurement=show_system_integrity_measurement_json
        )

        # Now the data model is 'shaped' correctly we need to validate the actual data
        # Validate each sudi certificate from each location
        sudi_certs = self._validate_v2_trust_chain(
            trust_chain=show_system_integrity_trust_chain_json
        )

        compliance_info = self._validate_v2_compliance(
            compliance=show_system_integrity_compliance_json, sudi_certs=sudi_certs
        )

        self._validate_v2_measurement(
            measurements=show_system_integrity_measurement_json,
            compliance_info=compliance_info,
            sudi_certs=sudi_certs,
        )
