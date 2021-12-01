import pytest
import gzip
import pathlib

from BootIntegrityValidator import BootIntegrityValidator


class TestBootIntegrityValidator(object):
    def setup(self):
        self.test_files = pathlib.Path(__file__).parent / "test_files"

    def test_invalid_custom_cert(self):
        kgv = open(self.test_files / "old_kgv_signed.json", "rb")
        kgv_sig = open(self.test_files / "old_kgv_signed.json.signature.bad", "rb")
        custom_cert = open(self.test_files / "bad_custom_cert.pem", "rb")
        with pytest.raises(BootIntegrityValidator.ValidationException):
            bi = BootIntegrityValidator(
                known_good_values=kgv.read(),
                known_good_values_signature=kgv_sig.read(),
                custom_signing_cert=custom_cert,
            )

    def test_kgv_invalid_signature(self):
        kgv = open(self.test_files / "old_kgv_signed.json", "rb")
        kgv_sig = open(self.test_files / "old_kgv_signed.json.signature.bad", "rb")
        with pytest.raises(BootIntegrityValidator.ValidationException):
            bi = BootIntegrityValidator(
                known_good_values=kgv.read(), known_good_values_signature=kgv_sig.read()
            )

    def test_invalid_device_cert(self):
        show_plat = open(self.test_files / "isr4k_show_plat_int.txt", "r")
        show_sudi = open(
            self.test_files / "isr4k_show_plat_sudi_sign_invalid_dev_cert.txt",
            "r",
        )
        kgv = open(self.test_files / "old_kgv_signed.json", "rb")
        kgv_sig = open(self.test_files / "old_kgv_signed.json.signature", "rb")
        bi = BootIntegrityValidator(
            known_good_values=kgv.read(), known_good_values_signature=kgv_sig.read()
        )
        with pytest.raises(BootIntegrityValidator.ValidationException):
            bi.validate(
                show_platform_integrity_cmd_output=show_plat.read(),
                show_platform_sudi_certificate_cmd_output=show_sudi.read(),
            )

    def test_validate_device_cert_valid_sign(self):
        show_sudi = open(self.test_files / "38_show_sudi_sign.txt", "r")
        kgv = open(self.test_files / "old_kgv_signed.json", "rb")
        kgv_sig = open(self.test_files / "old_kgv_signed.json.signature", "rb")
        bi = BootIntegrityValidator(
            known_good_values=kgv.read(), known_good_values_signature=kgv_sig.read()
        )
        bi._validate_device_cert(cmd_output=show_sudi.read())

    def test_validate_device_cert_invalid_sign_internal_function(self):
        show_sudi = open(self.test_files / "38_show_sudi_sign_bad.txt", "r")
        kgv = open(self.test_files / "old_kgv_signed.json", "rb")
        kgv_sig = open(self.test_files / "old_kgv_signed.json.signature", "rb")
        bi = BootIntegrityValidator(
            known_good_values=kgv.read(), known_good_values_signature=kgv_sig.read()
        )
        with pytest.raises(BootIntegrityValidator.ValidationException):
            bi._validate_device_cert(cmd_output=show_sudi.read())

    def test_validate_device_cert_invalid_sign(self):
        show_sudi = open(self.test_files / "38_show_sudi_sign_bad.txt", "r")
        show_plat = open(self.test_files / "38_show_plat_int_no_hash.txt", "r")
        kgv = open(self.test_files / "old_kgv_signed.json", "rb")
        kgv_sig = open(self.test_files / "old_kgv_signed.json.signature", "rb")
        bi = BootIntegrityValidator(
            known_good_values=kgv.read(), known_good_values_signature=kgv_sig.read()
        )
        with pytest.raises(BootIntegrityValidator.ValidationException):
            bi.validate(
                show_platform_integrity_cmd_output=show_plat.read(),
                show_platform_sudi_certificate_cmd_output=show_sudi.read(),
            )

    def test_validate_device_cert_valid_sig_nonce(self):
        show_sudi = open(self.test_files / "38_show_sudi_sign_nonce.txt", "r")
        kgv = open(self.test_files / "old_kgv_signed.json", "rb")
        kgv_sig = open(self.test_files / "old_kgv_signed.json.signature", "rb")
        bi = BootIntegrityValidator(
            known_good_values=kgv.read(), known_good_values_signature=kgv_sig.read()
        )
        bi._validate_device_cert(cmd_output=show_sudi.read())

    def test_validate_device_cert_not_present(self):
        show_plat_int = open(
            self.test_files / "cbr8_show_plat_int_sign_not_present.txt", "r"
        )
        show_plat_cert = open(
            self.test_files / "cbr8_show_plat_sudi_not_present.txt", "r"
        )
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        with pytest.raises(BootIntegrityValidator.MissingInfo):
            bi.validate(
                show_platform_integrity_cmd_output=show_plat_int.read(),
                show_platform_sudi_certificate_cmd_output=show_plat_cert.read(),
            )

    def test_validate_show_platform_integrity_valid_sign_internal_function(self):
        show_plat = open(self.test_files / "isr4k_show_plat_int_sign.txt", "r")
        dev_cert = open(self.test_files / "isr4k_device_cert.txt", "rb")
        dev_cert_obj = BootIntegrityValidator._load_cert_from_stream(f=dev_cert)
        BootIntegrityValidator._validate_show_platform_integrity_cmd_output_signature(
            cmd_output=show_plat.read(), device_cert_object=dev_cert_obj
        )

    def test_validate_show_platform_integrity_valid_sign(self):
        show_plat = open(self.test_files / "isr4k_show_plat_int_sign.txt", "r")
        show_sudi = open(self.test_files / "isr4k_show_plat_sudi_sign_nonce.txt", "r")
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        bi.validate(
            show_platform_integrity_cmd_output=show_plat.read(),
            show_platform_sudi_certificate_cmd_output=show_sudi.read(),
        )

    def test_validate_show_platform_integrity_valid_sign_nonce_internal_function(self):
        show_plat = open(self.test_files / "isr4k_show_plat_int_sign_nonce.txt", "r")
        dev_cert = open(self.test_files / "isr4k_device_cert.txt", "rb")
        dev_cert_obj = BootIntegrityValidator._load_cert_from_stream(f=dev_cert)
        BootIntegrityValidator._validate_show_platform_integrity_cmd_output_signature(
            cmd_output=show_plat.read(), device_cert_object=dev_cert_obj
        )

    def test_validate_show_platform_integrity_invalid_sign_internal_function(self):
        show_plat = open(self.test_files / "isr4k_show_plat_int_sign_bad.txt", "r")
        dev_cert = open(self.test_files / "isr4k_device_cert.txt", "rb")
        dev_cert_obj = BootIntegrityValidator._load_cert_from_stream(f=dev_cert)
        with pytest.raises(BootIntegrityValidator.ValidationException):
            BootIntegrityValidator._validate_show_platform_integrity_cmd_output_signature(
                cmd_output=show_plat.read(), device_cert_object=dev_cert_obj
            )

    def test_validate_show_platform_integrity_invalid_sign(self):
        show_plat = open(self.test_files / "isr4k_show_plat_int_sign_bad.txt", "r")
        show_sudi = open(self.test_files / "isr4k_show_plat_sudi_sign_nonce.txt", "r")
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        with pytest.raises(BootIntegrityValidator.ValidationException):
            bi.validate(
                show_platform_integrity_cmd_output=show_plat.read(),
                show_platform_sudi_certificate_cmd_output=show_sudi.read(),
            )

    def test_validate_show_platform_integrity_invalid_pcr0(self):
        show_plat = open(
            self.test_files / "isr4k_show_plat_int_sign_nonce_invalid_pcr0.txt",
            "r",
        )
        dev_cert = open(self.test_files / "isr4k_device_cert.txt", "rb")
        dev_cert_obj = BootIntegrityValidator._load_cert_from_stream(f=dev_cert)
        with pytest.raises(BootIntegrityValidator.ValidationException):
            BootIntegrityValidator._validate_show_platform_integrity_cmd_output_signature(
                cmd_output=show_plat.read(), device_cert_object=dev_cert_obj
            )

    def test_validate_show_platform_integrity_line_wrap(self):
        show_plat = open(self.test_files / "isr4k_show_plat_int_line_wrap.txt", "r")
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        with pytest.raises(BootIntegrityValidator.MissingInfo):
            bi.validate(show_platform_integrity_cmd_output=show_plat.read())

    def test_boot_0_version_invalid(self):
        show_plat = open(
            self.test_files / "isr4k_show_plat_int_bad_boot_0_version.txt", "r"
        )
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        with pytest.raises(BootIntegrityValidator.ValidationException):
            bi.validate(show_platform_integrity_cmd_output=show_plat.read())

    def test_boot_loader_version_invalid(self):
        show_plat = open(
            self.test_files / "isr4k_show_plat_int_bad_boot_loader_version.txt",
            "r",
        )
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        with pytest.raises(BootIntegrityValidator.ValidationException):
            bi.validate(show_platform_integrity_cmd_output=show_plat.read())

    def test_os_version_invalid(self):
        show_plat = open(
            self.test_files / "isr4k_show_plat_int_bad_os_version.txt", "r"
        )
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        with pytest.raises(BootIntegrityValidator.ValidationException):
            bi.validate(show_platform_integrity_cmd_output=show_plat.read())

    def test_boot0_hash_not_present(self):
        show_plat = open(self.test_files / "38_show_plat_int_no_hash.txt", "r")
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        with pytest.raises(BootIntegrityValidator.MissingInfo):
            bi.validate(show_platform_integrity_cmd_output=show_plat.read())

    def test_boot_loader_hash_not_present(self):
        show_plat = open(
            self.test_files / "isr4k_show_plat_int_not_present_boot_loader_hash.txt",
            "r",
        )
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        with pytest.raises(BootIntegrityValidator.MissingInfo):
            bi.validate(show_platform_integrity_cmd_output=show_plat.read())

    def test_os_version_not_present(self):
        show_plat = open(
            self.test_files / "isr4k_show_plat_int_not_present_os_version.txt",
            "r",
        )
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        with pytest.raises(BootIntegrityValidator.MissingInfo):
            bi.validate(show_platform_integrity_cmd_output=show_plat.read())

    def test_validate(self):
        show_plat = open(self.test_files / "isr4k_show_plat_int.txt", "r")
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        bi.validate(show_platform_integrity_cmd_output=show_plat.read())

    def test_validate_2099(self):
        show_plat_int = open(
            self.test_files / "isr1k_show_plat_int_sign_nonce.txt", "r"
        )
        show_plat_sudi = open(
            self.test_files / "isr1k_show_plat_sudi_sign_nonce.txt", "r"
        )
        kgv = gzip.open(self.test_files / "example_kgv.json.gzip", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        # SUDI for new platforms has a different PKI chain.  As long as signature validation doesn't fail this is good
        with pytest.raises(BootIntegrityValidator.ValidationException):
            bi.validate(
                show_platform_sudi_certificate_cmd_output=show_plat_sudi.read(),
                show_platform_integrity_cmd_output=show_plat_int.read(),
            )

    def test_validate_show_plat_int_multi_hashes(self):
        show_plat_cert = open(self.test_files / "isr4k_show_plat_sudi_cert.txt", "r")
        show_plat_int = open(
            self.test_files / "isr4k_show_plat_int_multi_hashes.txt", "r"
        )
        kgv = gzip.open(
            self.test_files / "example_kgv.json.gzip",
            "rb",
        )
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        bi.validate(
            show_platform_sudi_certificate_cmd_output=show_plat_cert.read(),
            show_platform_integrity_cmd_output=show_plat_int.read(),
        )

    def test_validate_show_plat_int_multi_bad_hashes(self):
        show_plat_cert = open(self.test_files / "isr4k_show_plat_sudi_cert.txt", "r")
        show_plat_int = open(
            self.test_files / "isr4k_show_plat_int_multi_bad_hashes.txt", "r"
        )
        kgv = gzip.open(
            self.test_files / "example_kgv.json.gzip",
            "rb",
        )
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        with pytest.raises(BootIntegrityValidator.ValidationException):
            bi.validate(
                show_platform_sudi_certificate_cmd_output=show_plat_cert.read(),
                show_platform_integrity_cmd_output=show_plat_int.read(),
            )

    def test_validate_v2_cli(self):
        kgv = open(
            self.test_files / "v2" / "sandbox.kgv.json",
            "rb",
        )
        bi = BootIntegrityValidator(known_good_values=kgv.read())

        trust_chain_cli = open(
            self.test_files / "v2" / "cli_valid_trust_chain.txt"
        ).read()
        compliance_cli = open(
            self.test_files / "v2" / "cli_valid_compliance.txt"
        ).read()
        measurement_cli = open(
            self.test_files / "v2" / "cli_valid_multiple_measure.txt"
        ).read()

        bi.validate_v2_cli(
            show_system_integrity_trust_chain_cmd_output=trust_chain_cli,
            show_system_integrity_compliance_cmd_output=compliance_cli,
            show_system_integrity_measurement_cmd_output=measurement_cli,
        )

    def test_validate_v2_xml(self):
        kgv = open(
            self.test_files / "v2" / "sandbox.kgv.json",
            "rb",
        )
        bi = BootIntegrityValidator(known_good_values=kgv.read())

        trust_chain_xml = open(
            self.test_files / "v2" / "netconf_valid_trust_chain.xml"
        ).read()
        compliance_xml = open(
            self.test_files / "v2" / "netconf_valid_compliance.xml"
        ).read()
        measurement_xml = open(
            self.test_files / "v2" / "netconf_valid_multiple_locations.xml"
        ).read()

        bi.validate_v2_xml(
            show_system_integrity_trust_chain_xml=trust_chain_xml,
            show_system_integrity_compliance_xml=compliance_xml,
            show_system_integrity_measurement_xml=measurement_xml,
        )
