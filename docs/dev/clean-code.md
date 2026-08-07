# Clean Code Philosophy

## Code Formatting and Linting with Ruff

The code in the **Wazuh Virtual Machines** repository must remain clean, well-formatted, and compliant with modern industry standards. To achieve this, we use [Ruff](https://docs.astral.sh/ruff/) for both formatting and linting.

Below are the commands to apply Ruff, depending on the scope and method you prefer:

---

### Code Formatting

#### Format all Wazuh Virtual Machines code

- Using Hatch:

  ```bash
  hatch run dev:ruff-format
  ```

- Using the command line:

  ```bash
  ruff format .
  ```

#### Format only the AMI-related code

- Using Hatch:

  ```bash
  hatch run dev-ami-configurer:ruff-format
  ```

- Using the command line:

  ```bash
  ruff format configurer/ami tests/test_configurer/test_ami
  ```

#### Format only the OVA-related code

- Using Hatch:

  ```bash
  hatch run dev-ova-pre-configurer:ruff-format
  hatch run dev-ova-post-configurer:ruff-format
  ```

- Using the command line:

  ```bash
  ruff format configurer/ova tests/test_configurer/test_ova
  ```

---

### Code Linting

#### Lint all Wazuh Virtual Machines code

- Using Hatch:

  ```bash
  hatch run dev:ruff-lint
  ```

- Using the command line:

  ```bash
  ruff check --fix --unsafe-fixes .
  ```

#### Lint only the AMI-related code

- Using Hatch:

  ```bash
  hatch run dev-ami-configurer:ruff-lint
  ```

- Using the command line:

  ```bash
  ruff check --fix --unsafe-fixes configurer/ami tests/test_configurer/test_ami
  ```

#### Lint only the OVA-related code

- Using Hatch:

  ```bash
  hatch run dev-ova-pre-configurer:ruff-lint
  hatch run dev-ova-post-configurer:ruff-lint
  ```

- Using the command line:

  ```bash
  ruff check --fix --unsafe-fixes configurer/ova tests/test_configurer/test_ova
  ```

---

### Combined Formatting and Linting (with Hatch only)

#### Format and lint all Wazuh Virtual Machines code

```bash
hatch run dev:fix
```

#### Format and lint AMI-related code

```bash
hatch run dev-ami-configurer:fix
```

#### Format and lint OVA-related code

```bash
hatch run dev-ova-pre-configurer:fix
hatch run dev-ova-post-configurer:fix
```
