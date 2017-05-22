import os
import sys
import unittest
import io

sys.path.insert(0, os.path.abspath('..'))
sys.path.insert(0, os.path.abspath('.'))
from BootIntegrityValidator import BootIntegrityValidator


class TestBootIntegrityValidator(unittest.TestCase):

    def setUp(self):
        self.path = os.path.abspath(".")
        kgv = open(self.path + "/test_files/old_kgv_signed.json", "rb")
        kgv_sig = open(self.path + "/test_files/old_kgv_signed.json.signature", "rb")
        self.bi = BootIntegrityValidator(known_good_values=kgv.read(), known_good_values_signature=kgv_sig.read())

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
        show_plat = open(self.path + "/test_files/isr4k_show_plat.txt", "r")
        show_sudi = open(self.path + "/test_files/show_sudi.txt.invalid_cert", "r")
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          self.bi.validate,
                          show_platform_integrity_cmd_output=show_plat.read(),
                          show_platform_sudi_certificate_cmd_output=show_sudi.read())

    def test_validate_device_cert_valid_sign(self):
        show_sudi = open(self.path + "/test_files/38_show_sudi_sign.txt", "r")
        self.bi._validate_device_cert(cmd_output=show_sudi.read())

    def test_validate_device_cert_invalid_sign_(self):
        show_sudi = open(self.path + "/test_files/38_show_sudi_sign_bad.txt", "r")
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          self.bi._validate_device_cert,
                          cmd_output=show_sudi.read())

    def test_validate_device_cert_valid_sig_nonce(self):
        show_sudi = open(self.path + "/test_files/38_show_sudi_sign_nonce.txt", "r")
        self.bi._validate_device_cert(cmd_output=show_sudi.read())

    def test_validate_show_platform_integrity_valid_sign(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_sign.txt", "r")
        dev_cert = open(self.path + "/test_files/isr4k_device_cert.txt", "rb")
        dev_cert_obj = BootIntegrityValidator._load_cert_from_stream(f=dev_cert)
        BootIntegrityValidator._validate_show_platform_integrity_cmd_output_signature(cmd_output=show_plat.read(),
                                                                                      device_cert_object=dev_cert_obj)

    def test_validate_show_platform_integrity_valid_sign_nonce(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_sign_nonce.txt", "r")
        dev_cert = open(self.path + "/test_files/isr4k_device_cert.txt", "rb")
        dev_cert_obj = BootIntegrityValidator._load_cert_from_stream(f=dev_cert)
        BootIntegrityValidator._validate_show_platform_integrity_cmd_output_signature(cmd_output=show_plat.read(),
                                                                                      device_cert_object=dev_cert_obj)

    def test_validate_show_platform_integrity_invalid_sign(self):
        show_plat = open(self.path + "/test_files/isr4k_show_plat_sign_bad.txt", "r")
        dev_cert = open(self.path + "/test_files/isr4k_device_cert.txt", "rb")
        dev_cert_obj = BootIntegrityValidator._load_cert_from_stream(f=dev_cert)
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          BootIntegrityValidator._validate_show_platform_integrity_cmd_output_signature,
                          cmd_output=show_plat.read(),
                          device_cert_object=dev_cert_obj)



    """
    def test_boot_0_valid(self):
        show_plat = open(self.path + "/test_files/show_plat.txt", "r")
        show_sudi = open(self.path + "/test_files/show_sudi.txt", "r")
        self.bi.validate(show_platform_integrity_cmd_output=show_plat.read(),
                         show_platform_sudi_certificate_cmd_output=show_sudi.read())




    def test_boot_0_not_found(self):
        a = 100 / 0

    def test_boot_0_invalid(self):
        a = 100 / 0

    def test_boot_loader_valid(self):
        a = 100 / 0

    def test_boot_loader_not_found(self):
        a = 100 / 0

    def test_boot_loader_invalid(self):
        a = 100 / 0

    def test_os_valid(self):
        a = 100 / 0

    def test_os_not_found(self):
        a = 100 / 0

    def test_os_invalid(self):
        a = 100 / 0

    def test_kgv_invalid_format(self):
        a = 100 / 0

    def test_no_product_found(self):
        a = 100 / 0
    """

if __name__ == "__main__":
    unittest.main(verbosity=2)
