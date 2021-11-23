import pathlib
import pytest
import pathlib
import shutil
import json

import BootIntegrityValidator.yang

TEST_FILES_DIR = pathlib.Path(__file__).parent / "test_files"


def test_yanglint_not_available(monkeypatch):
    monkeypatch.setattr(
        BootIntegrityValidator.yang, "YANGLINT_CMD", "not_a_real_command"
    )
    with pytest.raises(BootIntegrityValidator.yang.MissingDependencyError):
        BootIntegrityValidator.yang.validate_yang_models(files=[])


def test_validate_valid_yang_models():
    model_path = pathlib.Path(BootIntegrityValidator.yang.__path__[0])
    yang_models = [f for f in model_path.glob("*.yang")]
    BootIntegrityValidator.yang.validate_yang_models(files=yang_models)


def test_validate_invalid_yang_models(tmp_path):
    # Try to validate using only the single yang model (not its dependencies)
    yang_model_filename = "Cisco-IOS-XE-system-integrity-oper.yang"
    model_path = pathlib.Path(BootIntegrityValidator.yang.__path__[0])
    shutil.copy(
        str(model_path / yang_model_filename), str(tmp_path / yang_model_filename)
    )
    with pytest.raises(BootIntegrityValidator.yang.InvalidYangModel):
        BootIntegrityValidator.yang.validate_yang_models(
            files=[tmp_path / yang_model_filename]
        )


def test_validate_valid_xml_measurement():
    valid_xml_measurement = open(
        TEST_FILES_DIR / "v2" / "netconf_valid_measurement.xml"
    ).read()
    BootIntegrityValidator.yang.validate_xml_measurement(
        xml_measurement=valid_xml_measurement
    )


def test_validate_invalid_xml_measurement():
    """
    Common problem: Data model _may_ not include the fru, rp, fp, etc unless explicitly asked
    for in the netconf `get` request.
    """
    invalid_xml_measurement = open(
        TEST_FILES_DIR / "v2" / "netconf_invalid_measurement_no_list_key.xml"
    ).read()
    with pytest.raises(BootIntegrityValidator.yang.InvalidYangDataInstance):
        BootIntegrityValidator.yang.validate_xml_measurement(
            xml_measurement=invalid_xml_measurement
        )


def test_validate_valid_json_measurement():
    valid_json_measurement = json.load(
        open(TEST_FILES_DIR / "v2" / "restconf_valid_measurement.json")
    )
    BootIntegrityValidator.yang.validate_json_measurement(
        json_measurement=valid_json_measurement
    )


def test_validate_invalid_json_measurement():
    invalid_json_measurement = json.load(
        open(TEST_FILES_DIR / "v2" / "restconf_invalid_measurement_no_list_key.json")
    )
    with pytest.raises(BootIntegrityValidator.yang.InvalidYangDataInstance):
        BootIntegrityValidator.yang.validate_json_measurement(
            json_measurement=invalid_json_measurement
        )


def test_parse_cli_compliance():
    cmd_output = open(TEST_FILES_DIR / "v2" / "cli_valid_compliance.txt").read()
    json_data = (
        BootIntegrityValidator.yang.parse_show_system_integrity_all_compliance_nonce(
            cmd_output=cmd_output
        )
    )
    BootIntegrityValidator.yang.validate_json_measurement(json_measurement=json_data)


def test_parse_cli_trust_chain():
    cmd_output = open(TEST_FILES_DIR / "v2" / "cli_valid_trust_chain.txt").read()
    json_data = BootIntegrityValidator.yang.parse_show_system_integrity_switch_active_r0_trust_chain_nonce(
        cmd_output=cmd_output
    )
    BootIntegrityValidator.yang.validate_json_measurement(json_measurement=json_data)


def test_parse_cli_integrity_measure():
    cmd_output = open(TEST_FILES_DIR / "v2" / "cli_valid_multiple_measure.txt").read()
    json_data = BootIntegrityValidator.yang.parse_show_system_integrity_switch_active_r0_measurement_nonce(
        cmd_output=cmd_output
    )
    BootIntegrityValidator.yang.validate_json_measurement(json_measurement=json_data)
