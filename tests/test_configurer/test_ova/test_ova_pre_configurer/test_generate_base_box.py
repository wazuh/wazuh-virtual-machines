from unittest.mock import call, patch

import pytest

from configurer.ova.ova_pre_configurer.generate_base_box import (
    OS,
    OS_URL,
    check_dependencies,
    cleanup,
    convert_raw_to_vdi,
    convert_vmdk_to_raw,
    create_isolate_setup_configuration,
    create_virtualbox_vm,
    download_and_extract_ova,
    get_os_version,
    main,
    mount_and_setup_image,
    package_vagrant_box,
)


@pytest.fixture
def mock_run_command():
    with patch("configurer.ova.ova_pre_configurer.generate_base_box.run_command") as mock_generate_run_command:
        yield mock_generate_run_command


@pytest.fixture
def mock_shutil_rmtree():
    with patch("configurer.ova.ova_pre_configurer.generate_base_box.shutil.rmtree") as mock_shutil_rmtree:
        yield mock_shutil_rmtree


@pytest.fixture
def mock_os_path_exists():
    with patch("configurer.ova.ova_pre_configurer.generate_base_box.os.path.exists") as mock_exists:
        yield mock_exists


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
    mock_create_isolate.assert_called_once_with(path_to_mount_dir)
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


def test_create_isolate_setup_configuration_success(mock_run_command):
    dir_name = "/path/to/isolate_setup"
    commands = [
        f"mkdir -p {dir_name}/configurer/ova/ova_pre_configurer",
        f"mkdir -p {dir_name}/configurer/utils",
        f"mkdir -p {dir_name}/utils",
        f"cp configurer/ova/ova_pre_configurer/setup.py {dir_name}/configurer/ova/ova_pre_configurer/",
        f"cp configurer/utils/helpers.py {dir_name}/configurer/utils/",
        f"cp utils/logger.py {dir_name}/utils/",
    ]

    create_isolate_setup_configuration(dir_name)

    mock_run_command.assert_called_once_with(commands, check=True)


def test_convert_raw_to_vdi_success(mock_run_command):
    raw_file = "/path/to/source.raw"
    vdi_file = "/path/to/destination.vdi"
    command = f"vboxmanage convertfromraw {raw_file} {vdi_file} --format VDI"

    convert_raw_to_vdi(raw_file, vdi_file)

    mock_run_command.assert_called_once_with(command)


def test_create_virtualbox_vm_success(mock_run_command):
    vdi_file = "/path/to/destination.vdi"
    commands = [
        f"vboxmanage createvm --name {OS} --ostype Linux26_64 --register",
        f"vboxmanage modifyvm {OS} --memory 1024 --vram 16 --audio-enabled off",
        f"vboxmanage storagectl {OS} --name IDE --add ide",
        f"vboxmanage storagectl {OS} --name SATA --add sata --portcount 1",
        f"vboxmanage storageattach {OS} --storagectl IDE --port 1 --device 0 --type dvddrive --medium emptydrive",
        f"vboxmanage storageattach {OS} --storagectl SATA --port 0 --device 0 --type hdd --medium {vdi_file}",
    ]

    create_virtualbox_vm(vdi_file)

    mock_run_command.assert_called_once_with(commands)


def test_package_vagrant_box_success(mock_run_command):
    commands = [
        f"vagrant package --base {OS} --output {OS}.box",
        f"vboxmanage export {OS} -o {OS}.ova",
    ]

    package_vagrant_box()

    mock_run_command.assert_called_once_with(commands)


def test_cleanup_success(mock_run_command, mock_shutil_rmtree):
    temp_dirs = ["/path/to/temp1", "/path/to/temp2", "/path/to/temp3"]

    with patch("os.path.abspath", side_effect=lambda x: x), patch("os.path.exists", return_value=True):
        cleanup(temp_dirs)

    mock_shutil_rmtree.assert_has_calls([call(temp_dir) for temp_dir in temp_dirs], any_order=True)

    mock_run_command.assert_called_once_with(f"vboxmanage unregistervm {OS} --delete")


def test_get_os_version_success(mock_run_command):
    mock_response = [
        "HTTP/2 302 \ncontent-length: 0\nlocation: https://cdn.amazonlinux.com/al2023/os-images/2023.6.20250303.0/\ndate: Fri, 21 Mar 2025 17:29:20 GMT\nserver: AmazonS3\nx-amz-cf-pop: MAD53-P1\nvia: 1.1 fa8c2c6e6d3ef2d256a56b03615fe530.cloudfront.net (CloudFront), 1.1 29920174f36d25ac4e42a45c008ca846.cloudfront.net (CloudFront)\nx-cache: Miss from cloudfront\nx-amz-cf-pop: MAD53-P1\nx-amz-cf-id: 5_qO0KTFzQswEw0DxA2VsN6AtE4usmYP2BfioQQC2i5UbZ6Mc5nmWg=="
    ]
    mock_run_command.return_value = (mock_response, None, None)

    expected_version = "2023.6.20250303.0"
    actual_version = get_os_version()

    assert actual_version == expected_version
    mock_run_command.assert_called_once_with(f"curl -I {OS_URL}", output=True)


def test_get_os_version_no_location_header(mock_run_command):
    mock_response = "HTTP/1.1 302 Found\ncontent-type: text/html\n"
    mock_run_command.return_value = (mock_response, None, None)

    with pytest.raises(RuntimeError, match="Error getting OS version"):
        get_os_version()

    mock_run_command.assert_called_once_with(f"curl -I {OS_URL}", output=True)


def test_get_os_version_empty_response(mock_run_command):
    mock_response = ""
    mock_run_command.return_value = (mock_response, None, None)

    with pytest.raises(RuntimeError, match="Error getting OS version"):
        get_os_version()

    mock_run_command.assert_called_once_with(f"curl -I {OS_URL}", output=True)


def test_check_dependencies_all_present():
    with patch("configurer.ova.ova_pre_configurer.generate_base_box.shutil.which", return_value=True) as mock_which:
        check_dependencies()
        mock_which.assert_has_calls([call(cmd) for cmd in ["vboxmanage", "wget", "tar", "chroot"]], any_order=True)


def test_check_dependencies_missing_command():
    def mock_which_side_effect(cmd):
        return None if cmd == "wget" else f"/usr/bin/{cmd}"

    with (
        patch(
            "configurer.ova.ova_pre_configurer.generate_base_box.shutil.which", side_effect=mock_which_side_effect
        ) as mock_which,
        patch("configurer.ova.ova_pre_configurer.generate_base_box.logger.error") as mock_logger_error,
    ):
        with pytest.raises(Exception, match="Commands wget not found in PATH"):
            check_dependencies()

        print(mock_which.mock_calls)
        mock_which.assert_has_calls([call(cmd) for cmd in ["vboxmanage", "wget", "tar", "chroot"]], any_order=True)
        mock_logger_error.assert_called_once_with("Command wget not found in PATH")


def test_download_and_extract_ova_vmdk_exists(mock_os_path_exists, mock_run_command):
    version = "2023.6.20250303.0"
    vmdk_filename = "/path/to/existing.vmdk"
    ova_filename = "al2023-vmware_esx-2023.6.20250303.0-kernel-6.1-x86_64.xfs.gpt.ova"

    mock_os_path_exists.return_value = True

    download_and_extract_ova(version, vmdk_filename, ova_filename)

    mock_run_command.assert_not_called()
    mock_os_path_exists.assert_called_once_with(vmdk_filename)


def test_download_and_extract_ova_vmdk_not_exists(mock_os_path_exists, mock_run_command):
    version = "2023.6.20250303.0"
    vmdk_filename = "/path/to/nonexistent.vmdk"
    ova_filename = "al2023-vmware_esx-2023.6.20250303.0-kernel-6.1-x86_64.xfs.gpt.ova"

    mock_os_path_exists.return_value = False

    expected_commands = [
        f"wget https://cdn.amazonlinux.com/al2023/os-images/{version}/vmware/{ova_filename}",
        f"tar -xvf {ova_filename} {vmdk_filename}",
    ]

    download_and_extract_ova(version, vmdk_filename, ova_filename)

    mock_run_command.assert_called_once_with(expected_commands)
    mock_os_path_exists.assert_called_once_with(vmdk_filename)


@patch("configurer.ova.ova_pre_configurer.generate_base_box.logger.info_success")
@patch("configurer.ova.ova_pre_configurer.generate_base_box.logger.info")
@patch("configurer.ova.ova_pre_configurer.generate_base_box.cleanup")
@patch("configurer.ova.ova_pre_configurer.generate_base_box.package_vagrant_box")
@patch("configurer.ova.ova_pre_configurer.generate_base_box.create_virtualbox_vm")
@patch("configurer.ova.ova_pre_configurer.generate_base_box.convert_raw_to_vdi")
@patch("configurer.ova.ova_pre_configurer.generate_base_box.mount_and_setup_image")
@patch("configurer.ova.ova_pre_configurer.generate_base_box.convert_vmdk_to_raw")
@patch("configurer.ova.ova_pre_configurer.generate_base_box.download_and_extract_ova")
@patch("configurer.ova.ova_pre_configurer.generate_base_box.get_os_version")
@patch("configurer.ova.ova_pre_configurer.generate_base_box.check_dependencies")
@patch("configurer.ova.ova_pre_configurer.generate_base_box.tempfile.mkdtemp")
def test_main_success(
    mock_mkdtemp,
    mock_check_dependencies,
    mock_get_os_version,
    mock_download_and_extract_ova,
    mock_convert_vmdk_to_raw,
    mock_mount_and_setup_image,
    mock_convert_raw_to_vdi,
    mock_create_virtualbox_vm,
    mock_package_vagrant_box,
    mock_cleanup,
    mock_logger_info,
    mock_logger_info_success,
):
    mock_mkdtemp.side_effect = ["/tmp/raw_dir", "/tmp/vdi_dir", "/tmp/mount_dir"]

    mock_get_os_version.return_value = "2023.6.20250303.0"

    main()

    mock_check_dependencies.assert_called_once()

    mock_get_os_version.assert_called_once()

    mock_download_and_extract_ova.assert_called_once_with(
        "2023.6.20250303.0",
        "al2023-vmware_esx-2023.6.20250303.0-kernel-6.1-x86_64.xfs.gpt-disk1.vmdk",
        "al2023-vmware_esx-2023.6.20250303.0-kernel-6.1-x86_64.xfs.gpt.ova",
    )

    mock_convert_vmdk_to_raw.assert_called_once_with(
        "al2023-vmware_esx-2023.6.20250303.0-kernel-6.1-x86_64.xfs.gpt-disk1.vmdk",
        "/tmp/raw_dir/al2023.raw",
    )

    mock_mount_and_setup_image.assert_called_once_with("/tmp/raw_dir/al2023.raw", "/tmp/mount_dir")

    mock_convert_raw_to_vdi.assert_called_once_with("/tmp/raw_dir/al2023.raw", "/tmp/vdi_dir/al2023.vdi")

    mock_create_virtualbox_vm.assert_called_once_with("/tmp/vdi_dir/al2023.vdi")

    mock_package_vagrant_box.assert_called_once()

    mock_cleanup.assert_called_once_with(["/tmp/raw_dir", "/tmp/vdi_dir", "/tmp/mount_dir"])

    mock_logger_info.assert_any_call("--- Generating Base Box ---")
    mock_logger_info.assert_any_call("Executing cleanup.")
    mock_logger_info_success.assert_called_once_with("Base box generation completed.")
