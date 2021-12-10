This repo is a Python module that validates the Boot Integrity Visibility output generated on a Cisco IOS-XE device.
See [here](http://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3650/software/release/16-3/configuration_guide/b_163_consolidated_3650_cg/b_163_consolidated_3650_cg_chapter_01110010.pdf) for more information about the Cisco feature.

The module will cryptographically (integrity) validate the output to ensure that it was generated on the specified device.
Then the Boot 0, Boot Loader and OS integrity values will be checked against a database of "Known Good Values" (KGV) provided by Cisco.
This database of KGV will also be cryptographically validated that it was provided by Cisco.

This allows an administrator to validate the runtime state of the device and confirm that it is currently running genuine Cisco software

Checkout the documentation [on our github page](https://ciscodevnet.github.io/BootIntegrityValidator/)
