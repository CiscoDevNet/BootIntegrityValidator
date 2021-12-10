## BIV v2 commands

With Cisco IOS-XE 17.9 new commands were added to collect the BIV measurements. The data could be collected via:

- CLI via the commands
  - `show system integrity all compliance nonce 12345`
  - `show system integrity all trust-chain nonce 12345`
  - `show system integrity all measurement nonce 12345`
- NETCONF (XML YANG)
- RESTCONF (JSON YANG)

A new set of `validate_v2_xxxxx` functions have been added to validate the command output.

- `validate_v2_json` - function takes the JSON data response from RESTCONF and validates the data instance against the YANG model. Then the actual measurements are validated cryptographically against the SUDI certificates, ACT security chip and the Known-Good-Values Database.
- `validate_v2_xml` - function takes the XML data responses from NETCONF and validates the data instance against the YANG model. The data is transformed into a JSON data instance and then calls `validate_v2_json`.
- `validate_v2_cli` - function takes the CLI output, transforms it into a JSON data instance and then calls the `validate_v2_json` funtcion.

### Validation of BIV values (version 2)

#### CLI example

- [example_kgv.json](../base/example_kgv.json)
- [example_kgv.json.signature](../base/example_kgv.json.signature)
- [cli_valid_compliance](./cli_valid_compliance.txt)
- [cli_valid_trust_chain.txt](./cli_valid_trust_chain.txt)
- [cli_valid_measurement.txt](./cli_valid_measurement.txt)

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
#  CLI validation
#
#  Validatition function raises exceptions on validation failures as specified in V1
#
#####################################################################################
cli_trust_chain = open("cli_valid_trust_chain.txt", "r").read()
cli_compliance = open("cli_valid_compliance.txt", "r").read()
cli_measurement = open("cli_valid_measurement.txt", "r").read()

biv.validate_v2_cli(
    show_system_integrity_trust_chain_cmd_output=cli_trust_chain,
    show_system_integrity_compliance_cmd_output=cli_compliance,
    show_system_integrity_measurement_cmd_output=cli_measurement
)

```

#### XML example

- [example_kgv.json](../base/example_kgv.json)
- [example_kgv.json.signature](../base/example_kgv.json.signature)
- [netconf_valid_compliance.xml](./netconf_valid_compliance.xml)
- [netconf_valid_trust_chain.xml](./netconf_valid_trust_chain.xml)
- [netconf_valid_measurement.xml](./netconf_measurement.xml)

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
#  CLI validation
#
#  Validatition function raises exceptions on validation failures as specified in V1
#
#####################################################################################
netconf_trust_chain = open("netconf_valid_trust_chain.xml", "r").read()
netconf_compliance = open("netconf_valid_compliance.xml", "r").read()
netconf_measurement = open("netconf_valid_measurement.xml", "r").read()

biv.validate_v2_xml(
    show_system_integrity_trust_chain_xml=netconf_trust_chain,
    show_system_integrity_compliance_xml=netconf_compliance,
    show_system_integrity_measurement_xml=netconf_measurement
)

```

#### JSON example

- [example_kgv.json](../base/example_kgv.json)
- [example_kgv.json.signature](../base/example_kgv.json.signature)
- [restconf_valid_compliance.json](./restconf_valid_compliance.json)
- [restconf_valid_trust_chain.json](./restconf_valid_trust_chain.json)
- [restconf_valid_measurement.json](./restconf_measurement.json)

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
#  CLI validation
#
#  Validatition function raises exceptions on validation failures as specified in V1
#
#####################################################################################
restconf_trust_chain = open("restconf_valid_trust_chain.json", "r").read()
restconf_compliance = open("restconf_valid_compliance.json", "r").read()
restconf_measurement = open("restconf_valid_measurement.json", "r").read()

biv.validate_v2_json(
    show_system_integrity_trust_chain_json=restconf_trust_chain,
    show_system_integrity_compliance_json=restconf_compliance,
    show_system_integrity_measurement_json=measurement
)

```

### Exceptions

The `validate_v2_xxxxx` function will raise the exceptions as specified by the `validate` function regarding validation failures. However they may also raise the following exceptions types:

- `InvalidYangDataInstance` - The data instanct provided is not compliant against the YANG model.
- `InvalidYangModel` - The YANG models themselves are invalid. The model is included with this package but could be changed/updated within the `yang` folder of the distrubution
- `MissingDependencyError` - Failed to execute the command line tool `yanglint`. `yanglint` is the program that validates the YANG models and that the data instances against the model. The dependency can be installed via:
  - source - https://github.com/CESNET/libyang
  - apt (debian/ubuntu) package `yangtools` - http://manpages.ubuntu.com/manpages/focal/man1/yanglint.1.html
  - rpm (red hat/centos) package `libyang` https://centos.pkgs.org/8-stream/centos-appstream-x86_64/libyang-1.0.184-1.el8.x86_64.rpm.html
