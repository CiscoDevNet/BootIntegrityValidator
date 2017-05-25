.. _Exceptions:

Exceptions
==========



 If validation fails a custom exception will be raised for the following reasons:

- **BootIntegrityValidator.BootIntegrityValidator.ValidationException**

  - When calling validate() if the hashes do not match any of the valid hashes within the KGV file.  This is an indication of compromise of the device.
  - When initializing the object if validation of the signature file fails or the validation of the custom signing cert fails

- **BootIntegrityValidator.BootIntegrityValidator.VersionNotFound**

  - When calling validate() if the version of software used by the device is not within the KGV file.  It is not possible to determine whether or not the device is compromised.  Contact Cisco to obtain the latest KGV file.

- **BootIntegrityValidator.BootIntegrityValidator.ProductNotFound**

  - The product (the model number) was unable to be mapped to the 'product' in the KGV.  For example ISR4321/K9 should be mapped to "ISR4K".  The ProductFamily Object within BootIntegrityValidator/platforms.py may need to be updated.
  - The 'product' is not found within the KGV file. It is not possible to determine whether or not the device is compromised.  Contact Cisco to obtain the latest KGV file.

- **BootIntegrityValidator.BootIntegrityValidator.InvalidFormat**

  - If the KGV file is not formatted correctly.  Obtain a latest copy of the KGV file and a signature file to validate the file hasn't been modified.

.. code-block:: python

    # An instance of BootIntegrityValidator has already been initialized as 'biv'
    # with the known good values (KGV).

    show_plat_suid = open("example_show_plat_sudi.txt", "r")
    suid = show_plat_suid.read()

    show_plat_int = open("example_show_plat_int.txt", "r")
    spi = show_plat_int.read()


    try:
        biv.validate(show_platform_integrity_cmd_output=spi,
                     show_platform_sudi_certificate_cmd_output=suid)
        print("Successfully validated!")

    except BootIntegrityValidator.BootIntegrityValidator.InvalidFormat:
        print("know_good_values had an invalid format")

    except BootIntegrityValidator.BootIntegrityValidator.VersionNotFound:
        print("Version of software Not Found in known_good_values")

    except BootIntegrityValidator.BootIntegrityValidator.ProductNotFound:
        print("Product in cli output not mapped to 'product' in known_good_values")

    except BootIntegrityValidator.BootIntegrityValidator.ValidationException:
        print("Validation failed")
