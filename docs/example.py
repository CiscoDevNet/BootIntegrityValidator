import BootIntegrityValidator

kgv = open("example_kgv.json", "rb")
bi = BootIntegrityValidator.BootIntegrityValidator(known_good_values=kgv.read())

show_plat_suid = open("example_show_plat_sudi.txt", "r")
show_plat_int = open("example_show_plat_int.txt", "r")

try:
    bi.validate(show_platform_integrity_cmd_output=show_plat_int.read(),
                show_platform_sudi_certificate_cmd_output=show_plat_suid.read())
    print("Successfully validated!")
except BootIntegrityValidator.BootIntegrityValidator.InvalidFormat:
    print("know_good_values had an invalid format")
except BootIntegrityValidator.BootIntegrityValidator.VersionNotFound:
    print("Version of software Not Found in known_good_values")
except BootIntegrityValidator.BootIntegrityValidator.ProductNotFound:
    print("Product in cli output not mapped to 'product' in known_good_values")
except BootIntegrityValidator.BootIntegrityValidator.ValidationException:
    print("Validation failed")