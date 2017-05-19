import os
import sys
import unittest

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
        show_plat = open(self.path + "/test_files/show_plat.txt", "r")
        show_sudi = open(self.path + "/test_files/show_sudi.txt.invalid_cert", "r")
        self.assertRaises(BootIntegrityValidator.ValidationException,
                          self.bi.validate,
                          show_platform_integrity_cmd_output=show_plat.read(),
                          show_platform_sudi_certificate_cmd_output=show_sudi.read())


    def test_boot_0_valid(self):
        show_plat = open(self.path + "/test_files/show_plat.txt", "r")
        show_sudi = open(self.path + "/test_files/show_sudi.txt", "r")
        self.bi.validate(show_platform_integrity_cmd_output=show_plat.read(),
                         show_platform_sudi_certificate_cmd_output=show_sudi.read())



    """
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
