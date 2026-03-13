from pathlib import Path


class WazuhConfigMapping:
    """
    A class to handle the mapping of Wazuh configuration files.

    Attributes:
        replace_content (List[dict]): A list of dictionaries containing the path, keys, and values for the 'replace' type configuration.
    """

    def __init__(self, files_config: list[dict]):
        self.replace_content: list[dict] = self._set_content(files_config, "replace")

    def _set_content(self, files_config: list[dict], type: str) -> list[dict]:
        """
        Set the content for the given configuration files.

        This method processes a list of configuration files and extracts the content based on the specified type.
        It expects each file to have a 'path' and a section corresponding to the given type containing 'keys' and 'values'.

        Args:
            files_config (List[dict]): A list of dictionaries, each representing a configuration file.
            type (str): The type of content to extract from each configuration file.

        Returns:
            List[dict]: A list of dictionaries, each containing the 'path', 'keys', and 'values' from the configuration files.

        >>> files_config = [
        ...     {"path": "/path/to/file1", "replace": {"keys": ["key1", "key2"], "values": ["value1", "value2"]}},
        ...     {"path": "/path/to/file2", "replace": {"keys": ["key3"], "values": ["value3"]}},
        ... ]
        >>> wazuh_config_mapping = WazuhConfigMapping(files_config)
        >>> wazuh_config_mapping.replace_content
        return: [{'path': PosixPath('/path/to/file1'), 'keys':
        ['key1', 'key2'], 'values': ['value1', 'value2']}, {'path': PosixPath('/path/to/file2'),
        'keys: ['key3'], 'values': ['value3']}]

        Raises:
            KeyError: If the 'keys' or 'values' key is missing in the specified type section of a configuration file.
            KeyError: If the specified type or 'path' key is not found in a configuration file.
        """
        content = []
        for file in files_config:
            if (file_content := file.get(type, None)) and file.get("path", None):
                try:
                    content.append(
                        {
                            "path": Path(file["path"]),
                            "keys": file_content["keys"],
                            "values": file_content["values"],
                        }
                    )
                except KeyError as err:
                    raise KeyError(f"Missing 'keys' or 'values' key in '{type}' mapping file section: {err}") from err
            else:
                raise KeyError(f"The key '{type}' or 'path' was not found in the mapping file.")
        return content


class WazuhIndexerConfigMapping(WazuhConfigMapping):
    pass


class WazuhManagerConfigMapping(WazuhConfigMapping):
    pass


class WazuhDashboardConfigMapping(WazuhConfigMapping):
    pass


class WazuhAgentConfigMapping(WazuhConfigMapping):
    pass
