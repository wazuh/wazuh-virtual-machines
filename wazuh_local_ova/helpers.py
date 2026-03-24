import re
from pathlib import Path
from re import Pattern

from jinja2 import Environment, FileSystemLoader

from generic import exec_command


def render_vagrantfile(
    context: dict, template_dir: str, template_file: str = "Vagrantfile.j2", output_path: str = "Vagrantfile"
) -> None:
    """
    Renders a Vagrantfile from a Jinja2 template and writes it to a specified output file.

    Args:
        context (dict): A dictionary containing the variables to be used in the template rendering.
        template_dir (str): The directory where the Jinja2 template file is located.
        template_file (str, optional): The name of the Jinja2 template file. Defaults to "Vagrantfile.j2".
        output_path (str, optional): The path where the rendered Vagrantfile will be saved.

    Returns:
        None
    """

    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template(template_file)

    rendered_vagrantfile = template.render(context)

    with open(output_path, "w") as f:
        f.write(rendered_vagrantfile)


def get_wazuh_version(version_file: Path) -> str:
    """
    Get the Wazuh version from the given file.

    Args:
        version_file (str): The path to the version file.

    Returns:
        str: The Wazuh version.
    """
    with open(version_file) as file:
        version = file.read()
        match = re.search(r'"version"\s*:\s*"([^"]+)"', version)
        if match:
            return match.group(1)
        else:
            raise ValueError(f"Version not found in {version_file}")


def get_wazuh_stage(version_file: Path) -> str:
    """
    Get the Wazuh stage from the given file.

    Args:
        version_file (Path): The path to the version file.

    Returns:
        str: The Wazuh stage (e.g. ``"alpha0"``).
    """
    with open(version_file) as file:
        version = file.read()
        match = re.search(r'"stage"\s*:\s*"([^"]+)"', version)
        if match:
            return match.group(1)
        else:
            raise ValueError(f"Stage not found in {version_file}")


def vagrant_box_exists(box_name: str) -> bool:
    """
    Check whether a Vagrant box with the given name is already registered.

    Args:
        box_name (str): The name of the Vagrant box to look up.

    Returns:
        bool: ``True`` if the box is registered, ``False`` otherwise.
    """
    output, _ = exec_command("vagrant box list")
    return any(line.startswith(box_name) for line in output.splitlines())


def clean_output_lines(output: str, pattern: Pattern[str]) -> str:
    """
    Clean the output lines by removing lines that match the given pattern.

    Args:
        output (str): The output string to clean.
        pattern (Pattern[str]): The regex pattern to match lines to remove.

    Returns:
        str: The cleaned output string.
    """
    lines = output.splitlines()
    cleaned_lines = [line for line in lines if not re.search(pattern, line)]
    return "\n".join(cleaned_lines)
