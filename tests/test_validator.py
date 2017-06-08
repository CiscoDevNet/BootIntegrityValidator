import os
import sys
import unittest

sys.path.insert(0, os.path.abspath('..'))
sys.path.insert(0, os.path.abspath('.'))
from BootIntegrityValidator import BootIntegrityValidator


class TestBootIntegrityValidator(unittest.TestCase):

    def setUp(self):
        self.path = os.path.abspath(".")

    def test_invalid_custom_cert(self):
        kgv = open(self.path + "/test_files/old_kgv_signed.json", "rb")
        kgv_sig = open(self.path + "/test_files/old_kgv_signed.json.signature.bad", "rb")
        custom_cert = open(self.path + "/test_files/bad_custom_cert.pem", "rb")
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          BootIntegrityValidator,
                          known_good_values=kgv.read(),
                          known_good_values_signature=kgv_sig.read(),
                          custom_signing_cert=custom_cert)

    def test_kgv_invalid_signature(self):
        kgv = open(self.path + "/test_files/old_kgv_signed.json", "rb")
        kgv_sig = open(self.path + "/test_files/old_kgv_signed.json.signature.bad", "rb")
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          BootIntegrityValidator,
                          known_good_values=kgv.read(),
                          known_good_values_signature=kgv_sig.read())

    def test_invalid_device_cert(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int.txt", "r")
        show_sudi = open(self.path + "/test_files/isr4k_show_plat_sudi_sign_invalid_dev_cert.txt", "r")
        kgv = open(self.path + "/test_files/old_kgv_signed.json", "rb")
        kgv_sig = open(self.path + "/test_files/old_kgv_signed.json.signature", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read(), known_good_values_signature=kgv_sig.read())

        self.assertRaises(BootIntegrityValidator.ValidationException,
                          bi.validate,
                          show_platform_integrity_cmd_output=show_plat.read(),
                          show_platform_sudi_certificate_cmd_output=show_sudi.read())

    def test_validate_device_cert_valid_sign(self):
        show_sudi = open(self.path + "/test_files/38_show_sudi_sign.txt", "r")
        kgv = open(self.path + "/test_files/old_kgv_signed.json", "rb")
        kgv_sig = open(self.path + "/test_files/old_kgv_signed.json.signature", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read(), known_good_values_signature=kgv_sig.read())
        bi._validate_device_cert(cmd_output=show_sudi.read())

    def test_validate_device_cert_invalid_sign_(self):
        show_sudi = open(self.path + "/test_files/38_show_sudi_sign_bad.txt", "r")
        kgv = open(self.path + "/test_files/old_kgv_signed.json", "rb")
        kgv_sig = open(self.path + "/test_files/old_kgv_signed.json.signature", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read(), known_good_values_signature=kgv_sig.read())
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          bi._validate_device_cert,
                          cmd_output=show_sudi.read())

    def test_validate_device_cert_valid_sig_nonce(self):
        show_sudi = open(self.path + "/test_files/38_show_sudi_sign_nonce.txt", "r")
        kgv = open(self.path + "/test_files/old_kgv_signed.json", "rb")
        kgv_sig = open(self.path + "/test_files/old_kgv_signed.json.signature", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read(), known_good_values_signature=kgv_sig.read())
        bi._validate_device_cert(cmd_output=show_sudi.read())

    def test_validate_show_platform_integrity_valid_sign(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int_sign.txt", "r")
        dev_cert = open(self.path + "/test_files/isr4k_device_cert.txt", "rb")
        dev_cert_obj = BootIntegrityValidator._load_cert_from_stream(f=dev_cert)
        BootIntegrityValidator._validate_show_platform_integrity_cmd_output_signature(cmd_output=show_plat.read(),
                                                                                      device_cert_object=dev_cert_obj)

    def test_validate_show_platform_integrity_valid_sign_nonce(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int_sign_nonce.txt", "r")
        dev_cert = open(self.path + "/test_files/isr4k_device_cert.txt", "rb")
        dev_cert_obj = BootIntegrityValidator._load_cert_from_stream(f=dev_cert)
        BootIntegrityValidator._validate_show_platform_integrity_cmd_output_signature(cmd_output=show_plat.read(),
                                                                                      device_cert_object=dev_cert_obj)

    def test_validate_show_platform_integrity_invalid_sign(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int_sign_bad.txt", "r")
        dev_cert = open(self.path + "/test_files/isr4k_device_cert.txt", "rb")
        dev_cert_obj = BootIntegrityValidator._load_cert_from_stream(f=dev_cert)
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          BootIntegrityValidator._validate_show_platform_integrity_cmd_output_signature,
                          cmd_output=show_plat.read(),
                          device_cert_object=dev_cert_obj)

    def test_validate_show_platform_integrity_invalid_pcr0(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int_sign_nonce_invalid_pcr0.txt", "r")
        dev_cert = open(self.path + "/test_files/isr4k_device_cert.txt", "rb")
        dev_cert_obj = BootIntegrityValidator._load_cert_from_stream(f=dev_cert)
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          BootIntegrityValidator._validate_show_platform_integrity_cmd_output_signature,
                          cmd_output=show_plat.read(),
                          device_cert_object=dev_cert_obj)

    def test_validate_invalid_platform(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int_bad_platform.txt", "r")
        kgv = open(self.path + "/test_files/example_kgv.json", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        self.assertRaises(BootIntegrityValidator.ProductNotFound,
                          bi.validate,
                          show_platform_integrity_cmd_output=show_plat.read())

    def test_boot_0_version_not_found(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int_missing_boot_0_version.txt", "r")
        kgv = open(self.path + "/test_files/example_kgv.json", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        self.assertRaises(BootIntegrityValidator.VersionNotFound,
                          bi.validate,
                          show_platform_integrity_cmd_output=show_plat.read())

    def test_boot_0_version_invalid(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int_bad_boot_0_version.txt", "r")
        kgv = open(self.path + "/test_files/example_kgv.json", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          bi.validate,
                          show_platform_integrity_cmd_output=show_plat.read())

    def test_boot_loader_version_not_found(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int_missing_boot_0_version.txt", "r")
        kgv = open(self.path + "/test_files/example_kgv.json", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        self.assertRaises(BootIntegrityValidator.VersionNotFound,
                          bi.validate,
                          show_platform_integrity_cmd_output=show_plat.read())

    def test_boot_loader_version_invalid(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int_bad_boot_0_version.txt", "r")
        kgv = open(self.path + "/test_files/example_kgv.json", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          bi.validate,
                          show_platform_integrity_cmd_output=show_plat.read())

    def test_os_version_not_found(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int_missing_os_version.txt", "r")
        kgv = open(self.path + "/test_files/example_kgv.json", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        self.assertRaises(BootIntegrityValidator.VersionNotFound,
                          bi.validate,
                          show_platform_integrity_cmd_output=show_plat.read())

    def test_os_version_invalid(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int_bad_os_version.txt", "r")
        kgv = open(self.path + "/test_files/example_kgv.json", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          bi.validate,
                          show_platform_integrity_cmd_output=show_plat.read())

    def test_validate(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_int.txt", "r")
        kgv = open(self.path + "/test_files/example_kgv.json", "rb")
        bi = BootIntegrityValidator(known_good_values=kgv.read())
        bi.validate(show_platform_integrity_cmd_output=show_plat.read())

if __name__ == "__main__":
    unittest.main(verbosity=2)
