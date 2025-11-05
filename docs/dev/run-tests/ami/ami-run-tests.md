# Run AMI Tests

There are two types of tests designed to ensure the AMI works as expected:

## Unit Tests

These are standard unit tests that verify the internal logic of the code related to the AMI, ensuring it behaves correctly and without errors.

You can run the unit tests for the AMI using **Hatch** or directly from the **command line**:

- **Using Hatch**

  ```bash
  hatch run dev-ami-configurer:test-cov
  ```

- **Using the Command Line**

  ```bash
  FORCE_COLOR=1 pytest -n 4 \
    --cov=configurer/ami \
    --cov-report term-missing:skip-covered \
    tests/test_configurer/test_ami \
    --cov-report=xml
  ```

## Functionality Tests

These tests are responsible for validating the correct behavior of the AMI itself by creating an instance using the generated image and checking that all components and services work as expected.

> 🚧 Details on how to execute functionality tests will be provided later.
