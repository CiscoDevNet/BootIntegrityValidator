## BIV v2 commands

With Cisco IOS-XE 17.9

### Validation of BIV values (version 1)

Boot Integrity Values (BIV) are available using the following commands on the Cisco IOS-XE CLI: - `show platform integrity` - `show platform sudi`

To take the content from the command output and call the `validate` function on the `BootIntegrityValidator` object.

Files:

- [example_kgv.json](../base/example_kgv.json)
- [example_kgv.json.signature](../base/example_kgv.json.signature)
- [example_kgv.json.bad_signature](../base/example_kgv.json.bad_signature)
- [example_show_plat_int.txt](./example_show_plat_int.txt)
- [example_show_plat_sudi.txt](./example_show_plat_sudi.txt)

```python

kgv = open("example_kgv.json", "rb")
kgv_sig = open("example_kgv.json.signature", "rb")
kgv_bytes = kgv.read()

biv = BootIntegrityValidator.BootIntegrityValidator(
    known_good_values=kgv_bytes,
    known_good_values_signature=kgv_sig.read(),
    log_level=logging.DEBUG,
)

#####################################################################################
#
# Pass in the CLI output that has been save to file:
#       show platform sudi
#    and
#       show platform integrity
#
#####################################################################################
show_plat_suid = open("example_show_plat_sudi.txt", "r")
suid = show_plat_suid.read()

show_plat_int = open("example_show_plat_int.txt", "r")
spi = show_plat_int.read()

#####################################################################################
#
# The validate function will raise specific exceptions if validation fails
# or it is unable to validate the output.
#
#####################################################################################

try:
    biv.validate(
        show_platform_sudi_certificate_cmd_output=suid,
        show_platform_integrity_cmd_output=spi,
    )
    print("Successfully validated!")

except BootIntegrityValidator.BootIntegrityValidator.InvalidFormat:
    print("know_good_values had an invalid format")
    raise

except BootIntegrityValidator.BootIntegrityValidator.VersionNotFound:
    print("Version of software Not Found in known_good_values")
    raise

except BootIntegrityValidator.BootIntegrityValidator.ProductNotFound:
    print("Product in cli output not mapped to 'product' in known_good_values")
    raise

except BootIntegrityValidator.BootIntegrityValidator.ValidationException:
    print("Validation failed")
    raise


```
