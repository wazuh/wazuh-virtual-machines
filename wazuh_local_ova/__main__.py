from pathlib import Path

import typer

from .build_ova import configure_vagrant_vm, export_ova_image, generate_checksum, setup_execution_environment

app = typer.Typer()


@app.command(name="create", help="Create a new Wazuh OVA image.")
def create_ova(
    name: str = typer.Option("wazuh-local-ova", "--name", "-n", help="Name of the OVA image."),
    output: str = typer.Option(".", "--output", "-o", help="Output directory for the OVA image."),
    packages_url_path: str = typer.Option(..., "--packages_url_path", "-p", help="Path to the packages URL file."),
    checksum: bool = typer.Option(
        False,
        "--checksum",
        "-c",
        help="""Generate the SHA512 checksum of the generated OVA image. 
        If is set, this will be stored in the same path as the OVA image.""",
    ),
):
    """
    Create a new Wazuh OVA image.
    """
    setup_execution_environment(vm_name=name, packages_url_path=packages_url_path)
    vagrant_uuid = configure_vagrant_vm(packages_url_filename=Path(packages_url_path).name)
    export_ova_image(vagrant_uuid=vagrant_uuid, name=name, ova_dest=output)

    if checksum:
        generate_checksum(name=name, ova_dest=output)


if __name__ == "__main__":
    app()
