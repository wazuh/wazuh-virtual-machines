# Run OVA Tests

There are two types of tests designed to ensure the OVA works as expected:

## Unit Tests

These are standard unit tests that verify the internal logic of the code related to the OVA, ensuring it behaves correctly and without errors.

You can run the unit tests for the OVA using **Hatch** or directly from the **command line**. There are two Hatch environments: PreConfigurer and PostConfigurer. You can run the tests for each one of the environments:

### 1. PreConfigurer

- Using Hatch

  ```bash
  hatch run dev-ova-pre-configurer:test-cov
  ```

- Using the Command Line

  ```bash
  FORCE_COLOR=1 pytest -n 4 \
    --cov=configurer/ova/ova_pre_configurer \
    --cov-report term-missing:skip-covered \
    tests/test_configurer/test_ova/test_ova_pre_configurer \
    --cov-report=xml
  ```

### 2. PostConfigurer

- Using Hatch
  
  ```bash
  hatch run dev-ova-post-configurer:test-cov
  ```

- Using the Command Line

  ```bash
  FORCE_COLOR=1 pytest -n 4 \
    --cov=configurer/ova/ova_post_configurer \
    --cov-report term-missing:skip-covered \
    tests/test_configurer/test_ova/test_ova_post_configurer \
    --cov-report=xml
  ```

## Functionality Tests

These tests are responsible for validating the correct behavior of the OVA itself by importing the `.ova` file in a supported virtualization software (**VirtualBox** and **VMWare**), opening the Virtual Machine and checking that all components and services work as expected.

> 🚧 Details on how to execute functionality tests will be provided later.
