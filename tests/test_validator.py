import os
import sys
import unittest

sys.path.insert(0, os.path.abspath('..'))
sys.path.insert(0, os.path.abspath('.'))
from BootIntegrityValidator import BootIntegrityValidator as bi

class TestBootIntegrityValidator(unittest.TestCase):

    def test_boot_0_valid(self):
        c = bi()
        a = 100

    def test_boot_0_not_found(self):
        a = 100

    def test_boot_0_invalid(self):
        a = 100

    def test_boot_loader_valid(self):
        a = 100

    def test_boot_loader_not_found(self):
        a = 100

    def test_boot_loader_invalid(self):
        a = 100

    def test_os_valid(self):
        a = 100

    def test_os_not_found(self):
        a = 100

    def test_os_invalid(self):
        a = 100

    def test_kgv_invalid(self):
        a = 100

    def test_no_product_found(self):
        a = 100

if __name__ == "__main__":
    unittest.main(verbosity=2)
