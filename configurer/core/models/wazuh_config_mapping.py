from pathlib import Path
from typing import List


class WazuhConfigMapping:
    def __init__(self, files_config: List[dict]):
        self.replace_content: List[dict] = self._set_content(files_config, "replace")

    def _set_content(self, files_config: List[dict], type: str) -> List[dict]:
        content = []
        for file in files_config:
            if (file_content := file.get(type, None)) and file.get("path", None):
                try:
                    content.append(
                        {"path": Path(file["path"]), "keys": file_content["keys"], "values": file_content["values"]}
                    )
                except KeyError as err:
                    raise KeyError(f"Missing 'keys' or 'values' key in '{type}' mapping file section: {err}") from err
            else:
                raise KeyError(f"The key '{type}' or 'path' was not found in the mapping file.")
        return content


class WazuhIndexerConfigMapping(WazuhConfigMapping):
    pass


class WazuhServerConfigMapping(WazuhConfigMapping):
    pass


class WazuhDashboardConfigMapping(WazuhConfigMapping):
    pass
