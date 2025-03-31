from pathlib import Path
from unittest.mock import patch

from configurer.ami import ami_configurer_main
from configurer.ami.ami_pre_configurer.ami_customize import AmiCustomizer
from configurer.ami.ami_pre_configurer.utils.enums import AmiLocalFilePath


@patch("configurer.ami.main.Inventory")
@patch("configurer.ami.main.AmiCustomizer", spec=AmiCustomizer)
def test_main(mock_ami_customizer, mock_inventory, valid_inventory):
    # This main function will be modified when the post configurer is implemented.
    mock_inventory.return_value = valid_inventory
    ami_configurer_main(Path("test/path"))
    mock_ami_customizer.assert_called_once_with(
        inventory=valid_inventory,
        wazuh_banner_path=Path(AmiLocalFilePath.WAZUH_BANNER_LOGO),
        local_set_ram_script_path=Path(AmiLocalFilePath.SET_RAM_SCRIPT),
        local_update_indexer_heap_service_path=Path(AmiLocalFilePath.UPDATE_INDEXER_HEAP_SERVICE),
    )

    mock_ami_customizer.return_value.create_wazuh_user.assert_called_once()
    mock_ami_customizer.return_value.customize.assert_called_once()
