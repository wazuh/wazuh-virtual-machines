# Wazuh Virtual Machines Development Guide

This guide provides complete, step-by-step instructions for creating, configuring, testing, and generating both the AMI and OVA images for Wazuh using an All-in-One environment.

The guide is organized into the following sections:

- **Setup Environment**: Guide for configuring the development environment for both the AMI and the OVA. ([setup.md](setup.md))

- **Clean Code Philosophy**: Guide for maintaining clean code in both the AMI and OVA projects using formatters and linters. ([clean-code.md](clean-code.md))

- **Generate Artifact**: Step-by-step guide for generating the AMI and OVA artifacts. ([generate-artifact.md](generate-artifact/generate-artifact.md))
  - **AMI Artifact**: Step-by-step guide for generating the AMI image in AWS. ([ami-generate-artifact.md](generate-artifact/ami/ami-generate-artifact.md))
  - **OVA Artifact**: Step-by-step guide for generating the `.ova` image. ([ova-generate-artifact.md](generate-artifact/ova/ova-generate-artifact.md))

- **Run Tests**: Procedure for executing tests to validate the AMI and OVA artifacts. ([run-tests.md](run-tests/run-tests.md))
  - **AMI Tests**: Procedure for executing tests to validate the AMI. ([ami-run-tests.md](run-tests/ami/ami-run-tests.md))
  - **OVA Tests**: Procedure for executing tests to validate the OVA. ([ova-run-tests.md](run-tests/ova/ova-run-tests.md))
