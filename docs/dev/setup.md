# Set up the Development Environment

## Dependencies

The following dependencies are required to set up the development environment for the Wazuh OVA and AMI:

- **Git**
- **Python >= 3.8**
- **Pip**
- Plus some additionals packages listed in the toolchain

## Set Up the Toolchain

Our development process is carried out within a Python virtual environment. There are two supported ways to set up this environment:

### Option 1: Using [Hatch](https://hatch.pypa.io)

Hatch is a modern project manager for Python that simplifies environment management and task automation.

If you choose this approach, the only additional dependency you need to install manually is **Hatch** itself. Once installed, Hatch will handle the creation of isolated environments and manage all required dependencies for each task you want to perform.

To install Hatch:

```bash
pip install hatch
```

**Note:** Hatch requires Python **3.8 or later**.

### Option 2: Manual `venv` Setup

Alternatively, you can create and manage a virtual environment manually using Python's built-in `venv` module.

This approach requires that you have **Python 3.12 or higher** installed. After creating the virtual environment, you'll need to install the following dependencies:

```bash
pip install \
  pydantic \
  paramiko \
  pyyaml \
  jinja2 \
  pytest \
  pytest-cov \
  pytest-xdist \
  ruff \
  requests
```

Both approaches are valid. Choose the one that best fits your workflow or team preferences.

## Set Up the editor/debugger

Any editor and debugger can be used, feel free to use your favorite one.
