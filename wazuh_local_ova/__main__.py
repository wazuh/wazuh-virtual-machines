import logging
from pathlib import Path
from typing import Annotated

import typer

from .build_ova import (
    configure_vagrant_vm,
    export_ova_image,
    fetch_artifact_urls_file,
    generate_checksum,
    get_box_url_from_artifact_urls,
    setup_execution_environment,
)
from .enums import ArtifactFilePath, EnvironmentType

logger = logging.getLogger(__name__)
app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]})


@app.command(name="create", help="Create a new Wazuh OVA image.")
def create_ova(
    name: Annotated[str, typer.Option("--name", "-n", help="Name of the OVA image.")] = "wazuh-local-ova",
    output: Annotated[str, typer.Option("--output", "-o", help="Output directory for the OVA image.")] = ".",
    environment: Annotated[
        EnvironmentType,
        typer.Option(
            "--environment",
            "-e",
            help="Environment to use for fetching the Wazuh packages. ",
        ),
    ] = EnvironmentType.RELEASE,
    packages_url_path: Annotated[
        str,
        typer.Option(
            "--packages-url-path",
            "-p",
            help=(
                "Path to the local artifact URLs file or directory. "
                f"Only used when --environment is '{EnvironmentType.DEV}'."
            ),
        ),
    ] = ArtifactFilePath.DEV,
    checksum: Annotated[
        bool,
        typer.Option(
            "--checksum",
            "-c",
            help=(
                "Generate the SHA512 checksum of the generated OVA image. "
                "If set, this will be stored in the same path as the OVA image."
            ),
        ),
    ] = False,
):
    """
    Create a new Wazuh OVA image.
    """

    if environment == EnvironmentType.DEV:
        if packages_url_path and (not Path(packages_url_path).exists() or Path(packages_url_path).is_dir()):
            logger.error(
                f"The specified packages URL path '{packages_url_path}' does not exist or is a directory. "
                "Please provide a valid path to the local artifact URLs file using the --packages-url-path option or ensure the file exists at the default location."
            )
            raise typer.Exit(code=1)
        logger.info(f"Using development environment. The artifact URLs file to use is {packages_url_path}")
        artifact_urls_path = Path(packages_url_path)
    else:
        logger.info(f"Using {environment.value} environment.")
        artifact_urls_path = fetch_artifact_urls_file(
            environment=environment,
        )
    box_url = get_box_url_from_artifact_urls(artifact_urls_path)

    setup_execution_environment(
        vm_name=name,
        box_url=box_url,
    )
    vagrant_uuid = configure_vagrant_vm(packages_url_filename=artifact_urls_path.name)
    export_ova_image(vagrant_uuid=vagrant_uuid, name=name, ova_dest=output)

    if checksum:
        generate_checksum(name=name, ova_dest=output)


if __name__ == "__main__":
    app(prog_name="hatch run local-ova:create")
