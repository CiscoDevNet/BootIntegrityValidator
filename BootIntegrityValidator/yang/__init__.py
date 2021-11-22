import subprocess
import tempfile
import typing
import pathlib
import json
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
        run = subprocess.run([YANGLINT_CMD, *file_paths], capture_output=True)
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
        try:
            run = subprocess.run(
                args=[YANGLINT_CMD, "-f", "json", *model_paths, tmp_file_for_xml.name],
                capture_output=True,
                check=True,
            )
            if run.stderr:
                # yanglint for some reason returns with an exit code of 0 even in model validation failure
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
        except Exception as e:
            raise


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
        try:
            run = subprocess.run(
                args=[YANGLINT_CMD, "-f", "json", *model_paths, tmp_file_for_json.name],
                capture_output=True,
                check=True,
            )
            if run.stderr:
                # yanglint for some reason returns with an exit code of 0 even in model validation failure
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
        except Exception as e:
            raise
