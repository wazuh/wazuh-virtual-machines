from enum import StrEnum, auto


class EnvironmentType(StrEnum):
    RELEASE = auto()
    PRE_RELEASE = "pre-release"
    DEV = auto()


class ArtifactFilePath(StrEnum):
    RELEASE = "https://packages.wazuh.com/production/{major}.x/artifact_urls_{wazuh-version}.yaml"
    PRE_RELEASE = "https://packages-staging.xdrsiem.wazuh.info/pre-release/{major}.x/artifact_urls_{wazuh-version}-{wazuh-revision}.yaml"
    DEV = "./artifact_urls.yaml"

    def build(self, version: str = "", revision: str = "") -> str:
        """
        Resolve the URL/path template by substituting its placeholders.

        Uses ``str.format_map`` internally so hyphenated placeholder names
        (e.g. ``{wazuh-version}``) are supported. The ``major`` component is
        derived automatically from ``version`` (first segment before ``"."``).

        Args:
            version: Full Wazuh version string (e.g. ``"5.2.0"``).
            revision: Package revision string (e.g. ``"1"``).
                      Only required for ``PRE_RELEASE``.

        Returns:
            The resolved URL or path string.

        Examples:
            >>> ArtifactFilePath.RELEASE.build(version="5.2.0")
            'https://packages.wazuh.com/production/5.x/artifact_urls_5.2.0.yaml'

            >>> ArtifactFilePath.PRE_RELEASE.build(version="5.2.0", revision="1")
            'https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/artifact_urls_5.2.0-1.yaml'

            >>> ArtifactFilePath.DEV.build()
            './artifact_urls.yaml'
        """
        major = version.split(".")[0] if version else ""
        return self.value.format_map(
            {
                "major": major,
                "wazuh-version": version,
                "wazuh-revision": revision,
            }
        )
