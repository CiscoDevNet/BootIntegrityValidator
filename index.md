## Welcome to BootIntegrityValidator

This repo is a Python module that validates the Boot Integrity Visibility output generated on a Cisco IOS-XE device. See [the configuration guide](http://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3650/software/release/16-3/configuration_guide/b_163_consolidated_3650_cg/b_163_consolidated_3650_cg_chapter_01110010.pdf) for more information about the Cisco IOS-XE feature.

This python module will cryptographically (integrity) validate the output to ensure that it was generated on the specified device. Then the Boot 0, Boot Loader and OS integrity values will be checked against a database of "Known Good Values" (KGV) provided by Cisco. This database of KGV will also be cryptographically validated that it was provided by Cisco.

This allows an administrator to validate the runtime state of the device and confirm that it is currently running **genuine** Cisco software.

---

## Getting started

### Requirements

- `openssl`
- `yanglint` (optional) - A tool included in `libyang` [C library](https://github.com/CESNET/libyang) . The tool validates yang models and data instances against models. Only used in the `v2` validation methods

### Installation

```
python3 -m pip install BootIntegrityValidator
```

### Usage

1. [Initiazation of base object](./base/)
2. Validate devices:
   - [v1](./biv_v1) commands (Prior to Cisco IOS-XE 17.9)
   - [v2](./biv_v2) commands (Cisco IOS-XE 17.9+)
