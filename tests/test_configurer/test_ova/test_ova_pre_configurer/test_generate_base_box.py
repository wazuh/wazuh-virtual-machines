from unittest.mock import patch

import pytest

from configurer.ova.ova_pre_configurer.generate_base_box import convert_vmdk_to_raw, mount_and_setup_image


@pytest.fixture
def mock_run_command():
    with patch("configurer.ova.ova_pre_configurer.generate_base_box.run_command") as mock_generate_run_command:
        yield mock_generate_run_command


@patch("configurer.ova.ova_pre_configurer.generate_base_box.create_isolate_setup_configuration")
def test_mount_and_setup_image_success(mock_create_isolate, mock_run_command):
    path_to_mount_dir = "/path/to/mount_dir"
    path_to_raw_file = "/path/to/raw_file"
    commands = [
        f"mount -o bind /dev {path_to_mount_dir}/dev",
        f"mount -o bind /proc {path_to_mount_dir}/proc",
        f"mount -o bind /sys {path_to_mount_dir}/sys",
        f"chroot {path_to_mount_dir} python3 -m configurer.ova.ova_pre_configurer.setup",
        f"umount {path_to_mount_dir}/sys",
        f"umount {path_to_mount_dir}/proc",
        f"umount {path_to_mount_dir}/dev",
        f"umount {path_to_mount_dir}",
    ]
    mount_and_setup_image(path_to_raw_file, path_to_mount_dir)
    assert mock_run_command.call_count == 2
    mock_run_command.assert_any_call("mount -o loop,offset=12582912 /path/to/raw_file /path/to/mount_dir")
    mock_run_command.assert_any_call(commands)
    

def test_convert_vmdk_to_raw_success(mock_run_command):
    vmdk_filename = "/path/to/source.vmdk"
    raw_file = "/path/to/destination.raw"
    commands = [
        f"vboxmanage clonemedium {vmdk_filename} {raw_file} --format RAW",
        f"vboxmanage closemedium {vmdk_filename}",
        f"vboxmanage closemedium {raw_file}",
    ]

    convert_vmdk_to_raw(vmdk_filename, raw_file)

    mock_run_command.assert_called_once_with(commands)

def test_convert_vmdk_to_raw_failure(mock_run_command):
    mock_run_command.side_effect = Exception("Command failed")
    vmdk_filename = "/path/to/source.vmdk"
    raw_file = "/path/to/destination.raw"

    with pytest.raises(Exception, match="Command failed"):
        convert_vmdk_to_raw(vmdk_filename, raw_file)

    mock_run_command.assert_called_once()
