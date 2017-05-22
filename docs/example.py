import BootIntegrityValidator

# Open the Known good values files as and pass in 'bytes' to initialization function
kgv = open("example_kgv.json", "rb")
bi = BootIntegrityValidator.BootIntegrityValidator(known_good_values=kgv.read())

# Open the files that have show platform sudi and show platform integrity output and pass in as strings
# to the validate function
show_plat_suid = open("example_show_plat_sudi.txt", "r")
show_plat_int = open("example_show_plat_int.txt", "r")

# The validate function will raise specific exceptions if validation fails
# or it is unable to validate the output.
# If validation is successful the function will execute to completion without error
# and returns None

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

