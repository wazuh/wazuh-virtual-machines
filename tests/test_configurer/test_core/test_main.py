from pathlib import Path
from unittest.mock import patch

from configurer.core.core_configurer import CoreConfigurer
from configurer.core.main import main


@patch("configurer.core.main.Inventory")
@patch.object(CoreConfigurer, "configure")
def test_main_with_inventory(mock_configure, mock_inventory):
    main(inventory_path=Path("test_path"))

    mock_inventory.assert_called_once_with(inventory_path=Path("test_path"))
    mock_configure.assert_called_once()


@patch("configurer.core.main.Inventory")
@patch.object(CoreConfigurer, "configure")
def test_main_without_inventory(mock_configure, mock_inventory):
    main(inventory_path=None)

    mock_inventory.assert_not_called()
    mock_configure.assert_called_once()
