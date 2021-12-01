import subprocess
import tempfile
import typing
import pathlib
import json
import re
from .. import BootIntegrityValidator

YANGLINT_CMD = "yanglint"

__yang_model_validated = False


class MissingDependencyError(BootIntegrityValidator.BaseException):
    """

    Missing `yanglint` executable

    """


class InvalidYangModel(BootIntegrityValidator.BaseException):
    """

    The yang model definition failed validation by `yanglint`

    """


class InvalidYangDataInstance(BootIntegrityValidator.BaseException):
    """

    The yang data instance failed validation against the already validated data model

    """


def validate_yang_models(files: typing.List[pathlib.Path]) -> None:
    """
    Validates the yang models provided in the files
    :param files: typing.List[pathlib.Path] - the files containing the data models
    :returns None
    :raises: ValueError - If any part of the validation fails
    """
    file_paths = [str(f.absolute()) for f in files]
    try:
        run = subprocess.run(
            [YANGLINT_CMD, *file_paths], stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        if run.returncode:
            raise InvalidYangModel(
                f"""
The YANG definition file failed validation with the following command:

{run.args}

------ START OF STDOUT

{run.stdout.decode()}

------ START OF STDERR

{run.stderr.decode()}

------ END OF STDERR
            """
            )
    except FileNotFoundError:
        raise MissingDependencyError(
            """
BootIntegriyValidator has a dependency on the program 'yanglint'.

This software can be found via:
    source - https://github.com/CESNET/libyang 
    apt (debian/ubuntu) package 'yangtools' - http://manpages.ubuntu.com/manpages/focal/man1/yanglint.1.html
    rpm (red hat/centos) package 'libyang' https://centos.pkgs.org/8-stream/centos-appstream-x86_64/libyang-1.0.184-1.el8.x86_64.rpm.html
"""
        )


def validate_xml_measurement(xml_measurement: str) -> dict:
    """
    Takes a XML data instance of Cisco-IOS-XE-system-integrity-oper yang data model.
    Validates the data instance against the yang model and returns a JSON instance

    :param xml_measurement: str - the data instance of the NETCONF `get` operation
    :returns: dict - A dictionary of the JSON instance of the validated model
    """
    if not isinstance(xml_measurement, str):
        raise TypeError(
            f"xml_measurement received type '{type(xml_measurement)}' expecting 'str'"
        )

    model_path = pathlib.Path(__path__[0])
    if not __yang_model_validated:
        validate_yang_models(files=[f for f in model_path.glob("*.yang")])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml") as tmp_file_for_xml:
        tmp_file_for_xml.write(xml_measurement)
        tmp_file_for_xml.seek(0)
        model_paths = [str(f.absolute()) for f in model_path.glob("*.yang")]

        run = subprocess.run(
            args=[YANGLINT_CMD, "-f", "json", *model_paths, tmp_file_for_xml.name],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        if run.stderr or run.returncode:
            # yanglint for some reason returns with an exit code of 0 on mac even in model validation failure
            raise InvalidYangDataInstance(
                f"""
The data instance failed validation against the data model with the following error messages:

------ START OF STDOUT

{run.stdout.decode()}

------ START OF STDERR

{run.stderr.decode()}

------ END OF STDERR

If the error message is referring to "fru", "bay", "slot", "chassis", "node" being missing
make sure that it has been included in the NETCONF "get" request.

"""
            )

        return json.loads(run.stdout)


def validate_json_measurement(json_measurement: dict) -> dict:
    """
    Takes a XML data instance of Cisco-IOS-XE-system-integrity-oper yang data model.
    Validates the data instance against the yang model and returns a JSON instance

    :param xml_measurement: str - the data instance of the NETCONF `get` operation
    :returns: dict - A dictionary of the JSON instance of the validated model
    """
    if not isinstance(json_measurement, dict):
        raise TypeError(
            f"json_measurement received type '{type(json_measurement)}' expecting 'dict'"
        )

    model_path = pathlib.Path(__path__[0])
    if not __yang_model_validated:
        validate_yang_models(files=[f for f in model_path.glob("*.yang")])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as tmp_file_for_json:
        tmp_file_for_json.write(json.dumps(json_measurement))
        tmp_file_for_json.seek(0)
        model_paths = [str(f.absolute()) for f in model_path.glob("*.yang")]

        run = subprocess.run(
            args=[YANGLINT_CMD, "-f", "json", *model_paths, tmp_file_for_json.name],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        if run.stderr or run.returncode:
            # yanglint for some reason returns with an exit code of 0 on mac even in model validation failure
            raise InvalidYangDataInstance(
                f"""
The data instance failed validation against the data model with the following error messages:

------ START OF STDOUT

{run.stdout.decode()}

------ START OF STDERR

{run.stderr.decode()}

------ END OF STDERR

If the error message is referring to "fru", "bay", "slot", "chassis", "node" being missing
make sure that it has been included in the NETCONF "get" request.

"""
            )

        return json.loads(run.stdout)


def parse_show_system_integrity_measurement_nonce(cmd_output: str) -> dict:
    """
    Convert cli output into a correct JSON data instance

    Example output:
    Switch#show system integrity switch active R0 measurement nonce 1234

    ---------------------------------
    LOCATION FRU=BINOS_FRU_RP SLOT=0 BAY=0 CHASSIS=1 NODE=0
    ---------------------------------
    Platform: C9300-24T

    Boot Hashes:
    MA0081R06.1307262016: 80F5629CB70F2B4ABD89F118BF402A105E82E0A8A0AE5E7CD9E4D21F898CEFF5
    raswathn: D52A379917C48EA2B92E7837A9DADA8692611A6E008CEA7626F75FF5CB76480C5B53141929F9D60EE4D27BF248447247B02453EB9A22BBC058FD9657FF1008A3

    OS:
    Version: 2021-10-06_19.25_yisi
    Hashes:
    cat9k-test.bin: ADEC866CF1E77736506022BFF0116E1730D87E76426B72C03D5A0C459AB5DC56DFB3F81A0D3248474549838085382F5FA9ED120F8EED9E44A69FC37C5A68717C
    cat9k-wlc.2021-10-06_19.25_yisi.SSA.pkg: 7DD7915D098E76B4112666F592DB0D03E40D3F5CCCFB9B871B206A265ACBDC603A8579F2178CF8CB28EAD368831B9FE63002A77F54BD7E15356A42C53BE317B2
    cat9k-guestshell.2021-10-06_19.25_yisi.SSA.pkg: 70DC4A02340268AC60B3F76573F0444687CE2B492CBAF4FE02D06EC696A515E9EA4078216D29E536F40CB3094424E39F9EB12D60545616C10B57F716A1600CDF
    cat9k-webui.2021-10-06_19.25_yisi.SSA.pkg: 98718727FFE5509113DC1C2077E3C31161151A2B52AA412C92E6CF96463C05968F072E03BE72666B7ABA784BE2B8D39FF6802017DD75DF47CC32FE57039BEE26
    cat9k-cc_srdriver.2021-10-06_19.25_yisi.SSA.pkg: A3A9C4D40EFF844817FACE42B8A880A0B0D9A3B8C98561F757E2EBC9B197A4F79F11773A34F903CD86961CC4AB509CF18B2A2BC3E44F88FA9AC89214DBC19CAC
    cat9k-srdriver.2021-10-06_19.25_yisi.SSA.pkg: E12A2658D84DC3BD5BAF934C4399054A90B8451700A16A0214D43572C2C2E42D5B57649738122346DA39E6C1D1D676EB3A3D5E55D9CFB114ED2648717924CF7A
    cat9k-sipbase.2021-10-06_19.25_yisi.SSA.pkg: E4FD5A745B32D75419631D26908DAA5F219331A7AD6CD0CC127CDF7B62837A8C8D9B8FFAE9949EDC8D683B13DC72F418744F3FE89FAF6CA7A61D12C8336ED785
    cat9k-sipspa.2021-10-06_19.25_yisi.SSA.pkg: BCA5C003DE471D77A363411D74787DD20E0ACE5370BA0A32ADEBB0580E6F0193DB17159BF34475299CE5F19EC744142204235E7E36A993E3BD66A3AA9F4F7846
    cat9k-espbase.2021-10-06_19.25_yisi.SSA.pkg: 63D50B684488FDBF7DE537872D80B52762256D84BDAAA199337D6B1889F07CDDBEC81FA382DAA4FBD935D5604BDA560C10369A35D5BBF2391C1225F782797C9F
    cat9k-rpbase.2021-10-06_19.25_yisi.SSA.pkg: 5EB65F0FC3628DA3FA5AFBD154D68BF1D8381F8E62E3911A5A103649FF408C0132B5A86384162CE7C5E1CDCAF606AE3F535A56ECE211FC801A79C3F27E1D008A

    Registers:
    PCR0: E58879E961C31111A61CB91A720733AC3E153CFB13F6342254B942DD84ECC87A
    PCR8: 9D3E80C43CAD31158732962BDF7E73A98564017CD2ED079A11487345E1298238

    Signature:
    Version: 1
    Value: 0720E69B0CE0EB1C9AAA1DEB79C27454EF5CFC405426268F1595B0A7C9B009E4B5F8865850B13268EF8729ACAFAD0992E167EBA6CA8B29568D65ED61D7ADE0023B211848698EA61FEA60AC6C2DCFC7EA30A7909F7BB6FD7D168518B3F7A8D9D86B8984A08CEC595442A3A2AD34D71FC2D066D8DFA30370A160DFAFD5E875780F164D072FB71EF807047DEE94CD6384F488C83AD26D220FF69E09EC52DB4BA3353ECC1CC99454378137392432514C4B5C651750C94B8ABFB6DB7B86525C7F5B70D38049DF839DE083BB5CD787D76088FC0273F3EA5A3DAF8EE922289816345AF5E5074FD340AC8BEB8C79A9FE07A03B4AE5AEA418DC31A5B74F12388A303ADA1A



    """

    def command_chunker(measurement: str) -> typing.Tuple[dict, str]:
        location = {}
        for text in measurement.split("---------------------------------"):
            text = text.lstrip()
            if text.startswith("LOCATION FRU"):
                match = re.search(
                    pattern=r"LOCATION FRU=(?P<fru>\S+) SLOT=(?P<slot>\d+) BAY=(?P<bay>\d+) CHASSIS=(?P<chassis>-?\d+) NODE=(?P<node>\d+)",
                    string=text,
                )
                if not match:
                    raise ValueError(
                        "Unexpected format of 'show system integrity switch active <FRU> measurement nonce <INT>' received"
                    )
                match_dict = match.groupdict()
                location = {
                    "fru": match_dict["fru"],
                    "slot": int(match_dict["slot"]),
                    "bay": int(match_dict["bay"]),
                    "chassis": int(match_dict["chassis"]),
                    "node": int(match_dict["node"]),
                }
                continue
            elif text.startswith("Platform:"):
                yield (location, text)
                location = ""

    def parse_measurement(measurement: str) -> dict:

        # Extract the basic chunks of the output
        match = re.search(
            pattern=r"Platform:\s+(?P<platform>\S+).*Boot\sHashes:\n(?P<boot_hashes>.*)OS:\n\s*Version:\s(?P<os_version>\S+)\n\s*Hashes:\n(?P<os_hashes>.*)\s*Registers:\n\s*PCR0:\s(?P<pcr_0>\S+)\n\s*PCR8:\s(?P<pcr_8>\S*).*Signature:\n\s*Version:\s(?P<signature_version>\d+).*Value:[\s\n]*(?P<signature>\S*)",
            string=measurement,
            flags=re.DOTALL,
        )
        if not match:
            raise ValueError(
                "Unexpected format of 'show system integrity switch active <FRU> measurement nonce <INT>' received"
            )
        match_dict = match.groupdict()

        # Extract the boot loader hashes
        boot_loaders = []
        for (stage, line) in enumerate(match_dict["boot_hashes"].split("\n")):
            boot_loader_match = re.search(
                pattern=r"(?P<version>\S+):\s(?P<hash>\S+)", string=line
            )
            if boot_loader_match:
                boot_loaders.append({"stage": stage, **boot_loader_match.groupdict()})

        # Extract the os hashes
        oses = []
        for (index, line) in enumerate(match_dict["os_hashes"].split("\n")):
            os_match = re.search(pattern=r"(?P<name>\S+):\s(?P<hash>\S+)", string=line)
            if os_match:
                oses.append({"index": index, **os_match.groupdict()})

        return {
            "platform": match_dict["platform"],
            "boot-loader": boot_loaders,
            "operating-system": {
                "version": match_dict["os_version"],
                "package-integrity": oses,
            },
            "register": [
                {"index": 0, "pcr-content": match_dict["pcr_0"]},
                {"index": 8, "pcr-content": match_dict["pcr_8"]},
            ],
            "signature": {
                "signature": match_dict["signature"],
                "version": int(match_dict["signature_version"]),
            },
        }

    nonce_re = re.search(r"nonce\s+(\d+)", cmd_output)
    nonce = nonce_re.group(1) if nonce_re else None
    if nonce is None:
        raise ValueError(
            "Unexpected format of 'show system integrity switch active <FRU> measurement nonce <INT>' received"
        )

    locations = []
    for (location, location_measurement_str) in command_chunker(cmd_output):
        location_measurement = parse_measurement(measurement=location_measurement_str)
        location["integrity"] = [
            {
                "nonce": nonce,
                "request": "choice-measurement",
                "measurement": location_measurement,
            }
        ]
        locations.append(location)

    return {
        "Cisco-IOS-XE-system-integrity-oper:system-integrity-oper-data": {
            "location": locations
        }
    }


def parse_show_system_integrity_trust_chain_nonce(
    cmd_output: str,
) -> dict:
    """
    Convert cli output into a correct JSON data instance

    Example CLI output
    Switch#show system integrity switch active R0 trust_chain nonce 1234
    ---------------------------------
    LOCATION FRU=fru-rp SLOT=0 BAY=0 CHASSIS=1 NODE=0
    ---------------------------------
    Certificate Name: CRCA CERTIFICATE
    -----BEGIN CERTIFICATE-----
    MIIDITCCAgmgAwIBAgIJAZozWHjOFsHBMA0GCSqGSIb3DQEBCwUAMC0xDjAMBgNVBAoTBUNpc2Nv
    ....
    Rqg3QVVqYnFJUkNVN6j0dmmMVKZh17HgqLnFPKkmBlNQ9hQcNM3CSzVvEAK0CCEo/NJ/xzZ6WX1/
    f8Df1eXbFg==
    -----END CERTIFICATE-----
    Certificate Name: CMCA CERTIFICATE
    -----BEGIN CERTIFICATE-----
    MIIEZzCCA0+gAwIBAgIJCmR1UkzYYXxiMA0GCSqGSIb3DQEBCwUAMC0xDjAMBgNVBAoTBUNpc2Nv
    ....
    79GqVIbBTpOP2E6+1pBrE2jBNNocuBG1fgvh1qtJUdBbTziAKNoCo4sted6PW2/U
    -----END CERTIFICATE-----
    Certificate Name: SUDI CERTIFICATE
    -----BEGIN CERTIFICATE-----
    MIIDhTCCAm2gAwIBAgIEAZry5zANBgkqhkiG9w0BAQsFADAxMR8wHQYDVQQDExZIaWdoIEFzc3Vy
    ....
    k/3uCGVhOfpTeeuYol7PZob2Uw+/k6XPaQR4WvfQk2KF/fy7/6MrXv9hYA6XNs3/myQ=
    -----END CERTIFICATE-----

    Signature:
    Version: 1
    Value: 6C2E1A253B9739F9DA422B6779DCD6C2579820DB870AA2B2E0BA5C25F11771E5717325E0DD26DF87FB7C1D1E092E3A0B53B3D34570C4D5203D2AAD5A9BE6E9EA95B42990C05AF2BAC958EA953354867ED46A020313FB8955CAD5BFE854D05E3EBF16571921AF5E98DFA2A7A016FE42F7FE042001B455EBA7635D34D641F6A534BB0C9862C2D46888F5D722991D95CD0B882306AF9E9683BA2FDCC96855BAB8AD3C2CD984416C55BD626BE8A683F9AA9B4C1EC758AD9B9AF5C3BD35183B4A3237D525C0AB8EB789750D55044C64BA386BDC3D72A814EE2275C545A43EC4A0FCD54B6442138F48E3D82D3CD7FBEB7E802D75B9C7392F0ACADD5D1714B4072BB1E2


    """

    def command_chunker(measurement: str) -> typing.Tuple[dict, str]:
        location = {}
        for text in measurement.split("---------------------------------"):
            text = text.lstrip()
            if text.startswith("LOCATION FRU"):
                match = re.search(
                    pattern=r"LOCATION FRU=(?P<fru>\S+) SLOT=(?P<slot>\d+) BAY=(?P<bay>\d+) CHASSIS=(?P<chassis>-?\d+) NODE=(?P<node>\d+)",
                    string=text,
                )
                if not match:
                    raise ValueError(
                        "Unexpected format of 'show system integrity switch active <FRU> trust_chain nonce <INT>' received"
                    )
                match_dict = match.groupdict()
                location = {
                    "fru": match_dict["fru"],
                    "slot": int(match_dict["slot"]),
                    "bay": int(match_dict["bay"]),
                    "chassis": int(match_dict["chassis"]),
                    "node": int(match_dict["node"]),
                }
                continue
            elif text.startswith("Certificate Name:"):
                yield (location, text)
                location = ""

    def parse_measurement(measurement: str) -> dict:
        # Extract Certificates and Signature
        certificates = [
            match.groupdict()
            for match in re.finditer(
                pattern=r"Certificate Name:\s(?P<name>.*)\n\s*-----BEGIN CERTIFICATE-----\n(?P<value>[a-zA-Z0-9\/+=\n]*)\s+-----END CERTIFICATE-----\n?",
                string=measurement,
            )
        ]
        if not certificates:
            raise ValueError(
                "Unexpected format of 'show system integrity switch active <FRU> trust_chain nonce <INT>' received"
            )

        signature_match = re.search(
            pattern=r"Signature:\n\s+Version:\s(?P<version>\d+)\n\s+Value:\s+(?P<signature>\S+)",
            string=measurement,
        )
        if not signature_match:
            raise ValueError(
                "Unexpected format of 'show system integrity switch active <FRU> trust_chain nonce <INT>' received"
            )

        return {
            "trust-chain": certificates,
            "signature": {
                "signature": signature_match["signature"],
                "version": int(signature_match["version"]),
            },
        }

    nonce_re = re.search(r"nonce\s+(\d+)", cmd_output)
    nonce = nonce_re.group(1) if nonce_re else None
    if nonce is None:
        raise ValueError(
            "Unexpected format of 'show system integrity switch active <FRU> trust_chain nonce <INT>' received"
        )

    locations = []
    for (location, location_measurement_str) in command_chunker(cmd_output):
        location_measurement = parse_measurement(measurement=location_measurement_str)
        location["integrity"] = [
            {
                "nonce": nonce,
                "request": "choice-trust-chain",
                "trust-chain": location_measurement,
            }
        ]
        locations.append(location)

    return {
        "Cisco-IOS-XE-system-integrity-oper:system-integrity-oper-data": {
            "location": locations
        }
    }


def parse_show_system_integrity_compliance_nonce(cmd_output: str) -> dict:
    """
    Convert cli output into a correct JSON data instance

    Example cli output:
    system integrity all compliance nonce 12345
    ---------------------------------
    LOCATION FRU=fru-rp SLOT=0 BAY=0 CHASSIS=1 NODE=0
    ---------------------------------
    {"capabilities":{"secure_boot":true,"hwver_bootmeasure":false,"ldwm_envelope":false,"num_btlstage":2,"bivlen":64,"register_disabled":[{"pcr0":false},{"pcr8":false}]}}


    Signature:
    Version: 1
    Value:    0720E69B0CE0EB1C9AAA1DEB79C27454EF5CFC405426268F1595B0A7C9B009E4B5F8865850B13268EF8729ACAFAD0992E167EBA6CA8B29568D65ED61D7ADE0023B211848698EA61FEA60AC6C2DCFC7EA30A7909F7BB6FD7D168518B3F7A8D9D86B8984A08CEC595442A3A2AD34D71FC2D066D8DFA30370A160DFAFD5E875780F164D072FB71EF807047DEE94CD6384F488C83AD26D220FF69E09EC52DB4BA3353ECC1CC99454378137392432514C4B5C651750C94B8ABFB6DB7B86525C7F5B70D38049DF839DE083BB5CD787D76088FC0273F3EA5A3DAF8EE922289816345AF5E5074FD340AC8BEB8C79A9FE07A03B4AE5AEA418DC31A5B74F12388A303ADA1A#

    """

    def command_chunker(measurement: str) -> typing.Tuple[dict, str]:
        location = {}
        for text in measurement.split("---------------------------------"):
            text = text.lstrip()
            if text.startswith("LOCATION FRU"):
                match = re.search(
                    pattern=r"LOCATION FRU=(?P<fru>\S+) SLOT=(?P<slot>\d+) BAY=(?P<bay>\d+) CHASSIS=(?P<chassis>-?\d+) NODE=(?P<node>\d+)",
                    string=text,
                )
                if not match:
                    raise ValueError(
                        "Unexpected format of 'show system integrity all compliance nonce <INT>' received"
                    )
                match_dict = match.groupdict()
                location = {
                    "fru": match_dict["fru"],
                    "slot": int(match_dict["slot"]),
                    "bay": int(match_dict["bay"]),
                    "chassis": int(match_dict["chassis"]),
                    "node": int(match_dict["node"]),
                }
                continue
            elif text.startswith("Compliance:"):
                yield (location, text)
                location = ""

    def parse_measurement(measurement: str) -> dict:
        match = re.search(
            pattern=r'(?P<value>{"capabilities":.*)\n', string=measurement
        )
        if not match:
            raise ValueError(
                "Unexpected format of 'show system integrity all compliance nonce <INT>' received"
            )
        match_dict = match.groupdict()

        signature_match = re.search(
            pattern=r"Signature:\n\s+Version:\s(?P<version>\d+)\n\s+Value:\s+(?P<signature>\S+)",
            string=measurement,
        )
        if not signature_match:
            raise ValueError(
                "Unexpected format of 'show system integrity all compliance nonce <INT>' received"
            )

        return {
            "category": match_dict["value"],
            "signature": {
                "signature": signature_match["signature"],
                "version": int(signature_match["version"]),
            },
        }

    nonce_re = re.search(r"nonce\s+(\d+)", cmd_output)
    nonce = nonce_re.group(1) if nonce_re else None
    if nonce is None:
        raise ValueError(
            "Unexpected format of 'show system integrity switch active <FRU> trust_chain nonce <INT>' received"
        )

    locations = []
    for (location, location_measurement_str) in command_chunker(cmd_output):
        location_measurement = parse_measurement(measurement=location_measurement_str)
        location["integrity"] = [
            {
                "nonce": nonce,
                "request": "choice-compliance",
                "compliance": location_measurement,
            }
        ]
        locations.append(location)

    return {
        "Cisco-IOS-XE-system-integrity-oper:system-integrity-oper-data": {
            "location": locations
        }
    }
