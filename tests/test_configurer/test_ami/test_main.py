from pathlib import Path
from unittest.mock import patch

import pytest

from configurer.ami import ami_configurer_main, ami_post_configurer, ami_pre_configurer
from configurer.ami.ami_post_configurer.ami_post_configurer import AmiPostConfigurer
from configurer.ami.ami_pre_configurer.ami_pre_configurer import AmiPreConfigurer
from configurer.ami.ami_pre_configurer.utils.enums import AmiLocalFilePath


@patch("configurer.ami.main.Inventory")
@patch("configurer.ami.main.ami_pre_configurer")
def test_main_with_pre_configurer(mock_ami_pre_configurer, mock_inventory, valid_inventory):
    mock_inventory.return_value = valid_inventory

    ami_configurer_main(inventory_path=Path("test/path"), type="ami-pre-configurer")
    mock_ami_pre_configurer.assert_called_once_with(inventory=valid_inventory)


@patch("configurer.ami.main.Inventory")
@patch("configurer.ami.main.ami_post_configurer")
def test_main_with_post_configurer(mock_ami_post_configurer, mock_inventory, valid_inventory):
    mock_inventory.return_value = valid_inventory

    ami_configurer_main(inventory_path=Path("test/path"), type="ami-post-configurer")
    mock_ami_post_configurer.assert_called_once_with(inventory=valid_inventory)


@patch("configurer.ami.main.Inventory")
def test_main_without_correct_type(mock_inventory):
    with pytest.raises(ValueError, match="Invalid type. Expected 'ami-pre-configurer' or 'ami-post-configurer'."):
        ami_configurer_main(inventory_path=Path("test/path"), type="invalid-type")  # type: ignore


@patch("configurer.ami.main.Inventory")
@patch("configurer.ami.main.AmiPreConfigurer", spec=AmiPreConfigurer)
def test_ami_pre_configurer(mock_ami_pre_configurer_class, mock_inventory, valid_inventory):
    ami_pre_configurer(inventory=valid_inventory)
    mock_ami_pre_configurer_class.assert_called_once_with(
        inventory=valid_inventory,
        wazuh_banner_path=Path(AmiLocalFilePath.WAZUH_BANNER_LOGO),
        local_set_ram_script_path=Path(AmiLocalFilePath.SET_RAM_SCRIPT),
        local_update_indexer_heap_service_path=Path(AmiLocalFilePath.UPDATE_INDEXER_HEAP_SERVICE),
        local_customize_certs_service_path=Path(AmiLocalFilePath.CUSTOMIZE_CERTS_SERVICE),
        local_customize_certs_timer_path=Path(AmiLocalFilePath.CUSTOMIZE_CERTS_TIMER),
        local_customize_debug_script_path=Path(AmiLocalFilePath.CUSTOMIZE_DEBUG_SCRIPT),
    )

    mock_ami_pre_configurer_class.return_value.create_wazuh_user.assert_called_once()
    mock_ami_pre_configurer_class.return_value.customize.assert_called_once()


@patch("configurer.ami.main.Inventory")
@patch("configurer.ami.main.AmiPostConfigurer", spec=AmiPostConfigurer)
def test_ami_post_configurer(mock_ami_post_configurer_class, mock_inventory, valid_inventory):
    ami_post_configurer(inventory=valid_inventory)
    mock_ami_post_configurer_class.assert_called_once_with(inventory=valid_inventory)
    mock_ami_post_configurer_class.return_value.post_customize.assert_called_once()
