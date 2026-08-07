import os
from unittest.mock import MagicMock, patch

import pytest

from configurer.ami.ami_post_configurer.create_service_directory import (
    copy_file_to_directory,
    create_directory,
    create_directory_structure,
    generate_yaml,
)


@pytest.fixture
def mock_exec_command(autouse=True):
    mock_exec_command = MagicMock()
    with patch("configurer.ami.ami_post_configurer.create_service_directory.exec_command", mock_exec_command):
        mock_exec_command.return_value = "", ""
        yield mock_exec_command


@patch("configurer.ami.ami_post_configurer.create_service_directory.create_directory")
@patch("configurer.ami.ami_post_configurer.create_service_directory.copy_file_to_directory")
def test_create_directory_structure_with_nested_directories(
    mock_copy_file_to_directory, mock_create_directory, mock_paramiko
):
    base_path = "/base/path"
    remote_user = "test_user"
    directory_template = {
        "name": "root_dir",
        "files": [{"path": "/local/file1.txt", "local": True}],
        "directories": [
            {
                "name": "sub_dir1",
                "files": [{"path": "/local/file2.txt", "local": False}],
                "directories": [{"name": "sub_sub_dir", "files": [{"path": "/local/file3.txt", "local": True}]}],
            }
        ],
    }

    create_directory_structure(base_path, directory_template, remote_user, mock_paramiko.return_value)

    mock_create_directory.assert_any_call("/base/path/root_dir", mock_paramiko.return_value)
    mock_create_directory.assert_any_call("/base/path/root_dir/sub_dir1", mock_paramiko.return_value)
    mock_create_directory.assert_any_call("/base/path/root_dir/sub_dir1/sub_sub_dir", mock_paramiko.return_value)

    mock_copy_file_to_directory.assert_any_call(
        "/local/file1.txt", "/base/path/root_dir", remote_user, mock_paramiko.return_value, True
    )
    mock_copy_file_to_directory.assert_any_call(
        "/local/file2.txt", "/base/path/root_dir/sub_dir1", remote_user, mock_paramiko.return_value, False
    )
    mock_copy_file_to_directory.assert_any_call(
        "/local/file3.txt", "/base/path/root_dir/sub_dir1/sub_sub_dir", remote_user, mock_paramiko.return_value, True
    )


@patch("configurer.ami.ami_post_configurer.create_service_directory.create_directory")
@patch("configurer.ami.ami_post_configurer.create_service_directory.copy_file_to_directory")
def test_create_directory_structure_with_empty_template(
    mock_copy_file_to_directory, mock_create_directory, mock_paramiko
):
    base_path = "/base/path"
    remote_user = "test_user"
    directory_template = {"name": "empty_dir", "files": [], "directories": []}

    create_directory_structure(base_path, directory_template, remote_user, mock_paramiko.return_valu)

    mock_create_directory.assert_called_once_with("/base/path/empty_dir", mock_paramiko.return_valu)

    mock_copy_file_to_directory.assert_not_called()


def test_create_directory_success(mock_exec_command, mock_logger, mock_paramiko):
    path = "/test/path"

    create_directory(path, mock_paramiko.return_value)

    command = f"sudo mkdir -p {path}"
    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with(f"Directory {path} created successfully")


def test_create_directory_error(mock_exec_command, mock_logger, mock_paramiko):
    path = "/test/path"
    mock_exec_command.return_value = ("", "Error creating directory")

    with pytest.raises(RuntimeError, match="Error creating directory /test/path: Error creating directory"):
        create_directory(path, mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with(f"Error creating directory {path}")


def test_copy_file_to_directory_local_success(mock_exec_command, mock_logger, mock_paramiko):
    file_path = "/test/file.txt"
    directory_path = "/test/directory"
    remote_user = "test_user"
    local = True
    sftp = mock_paramiko.return_value.open_sftp.return_value

    copy_file_to_directory(file_path, directory_path, remote_user, mock_paramiko.return_value, local)

    command = f"sudo mv /home/{remote_user}/{os.path.basename(file_path)} {directory_path}"

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)
    sftp.put.assert_called_once_with(file_path, f"/home/{remote_user}/{os.path.basename(file_path)}")

    mock_logger.debug.assert_called_once_with(f"Local file {file_path} copied to {directory_path} remote directory")


def test_copy_file_to_directory_local_sftp_error(mock_exec_command, mock_logger, mock_paramiko):
    file_path = "/test/file.txt"
    directory_path = "/test/directory"
    remote_user = "test_user"
    local = True
    sftp = mock_paramiko.return_value.open_sftp.return_value
    sftp.put.side_effect = Exception("SFTP error")

    with pytest.raises(RuntimeError, match="Error copying file /test/file.txt to /test/directory: SFTP error"):
        copy_file_to_directory(file_path, directory_path, remote_user, mock_paramiko.return_value, local)

    mock_logger.error.assert_called_once_with(f"Error copying file {file_path} to {directory_path}")


def test_copy_file_to_directory_local_command_error(mock_exec_command, mock_logger, mock_paramiko):
    file_path = "/test/file.txt"
    directory_path = "/test/directory"
    remote_user = "test_user"
    local = True
    mock_exec_command.return_value = ("", "Error copying file")

    with pytest.raises(RuntimeError, match="Error copying file /test/file.txt to /test/directory: Error copying file"):
        copy_file_to_directory(file_path, directory_path, remote_user, mock_paramiko.return_value, local)

    mock_logger.error.assert_called_once_with(f"Error copying file {file_path} to {directory_path}")


def test_copy_file_to_directory_remote_success(mock_exec_command, mock_logger, mock_paramiko):
    file_path = "/test/file.txt"
    directory_path = "/test/directory"
    remote_user = "test_user"
    local = False
    sftp = mock_paramiko.return_value.open_sftp.return_value

    copy_file_to_directory(file_path, directory_path, remote_user, mock_paramiko.return_value, local)

    command = f"sudo cp {file_path} {directory_path}"

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)
    sftp.put.assert_not_called()

    mock_logger.debug.assert_called_once_with(f"Remote file {file_path} copied to {directory_path} remote directory")


def test_copy_file_to_directory_remote_command_error(mock_exec_command, mock_logger, mock_paramiko):
    file_path = "/test/file.txt"
    directory_path = "/test/directory"
    remote_user = "test_user"
    local = False
    mock_exec_command.return_value = ("", "Error copying file")
    sftp = mock_paramiko.return_value.open_sftp.return_value

    with pytest.raises(RuntimeError, match="Error copying file /test/file.txt to /test/directory: Error copying file"):
        copy_file_to_directory(file_path, directory_path, remote_user, mock_paramiko.return_value, local)

    sftp.put.assert_not_called()
    mock_logger.error.assert_called_once_with(f"Error copying file {file_path} to {directory_path}")


@patch("configurer.ami.ami_post_configurer.create_service_directory.Environment", autospec=True)
@patch("configurer.ami.ami_post_configurer.create_service_directory.FileSystemLoader", autospec=True)
def test_generate_yaml(mock_jinja_loader, mock_jinja_environment):
    renderer_yaml = """
    test_key: result1
    test_key2: result2
    """

    context = {
        "test_value": "value1",
        "test_value2": "value2",
    }

    mock_template = MagicMock()
    mock_template.render.return_value = renderer_yaml

    mock_env_instance = MagicMock()
    mock_env_instance.get_template.return_value = mock_template
    mock_jinja_environment.return_value = mock_env_instance

    result = generate_yaml(context=context, template_dir="template_dir", template_file="template_file")

    assert result == {
        "test_key": "result1",
        "test_key2": "result2",
    }
    mock_env_instance.get_template.assert_called_once_with("template_file")
    mock_template.render.assert_called_once_with(context)
