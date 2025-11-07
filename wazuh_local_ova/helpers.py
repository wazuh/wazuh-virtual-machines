import re
from pathlib import Path
from re import Pattern

from jinja2 import Environment, FileSystemLoader


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
