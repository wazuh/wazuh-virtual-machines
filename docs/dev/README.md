# Wazuh Virtual Machines Development Guide

This guide provides complete, step-by-step instructions for creating, configuring, testing, and generating both the AMI and OVA images for Wazuh using an All-in-One environment.

The guide is organized into the following sections:

- **Setup Environment**: Guide for configuring the development environment for both the AMI and the OVA. ([setup.md](setup.md))

- **Clean Code Philosophy**: Guide for maintaining clean code in both the AMI and OVA projects using formatters and linters. ([clean-code.md](clean-code.md))

- **AMI Development**  
  - **Generate Artifact**: Step-by-step guide for generating the AMI image in AWS. ([ami-generate-artifact.md](ami/ami-generate-artifact.md))
  - **Run Tests**: Procedure for executing tests to validate the AMI. ([ami-run-tests.md](ami/ami-run-tests.md))

- **OVA Development**  
  - **Generate Artifact**: Step-by-step guide for generating the `.ova` image. ([ova-generate-artifact.md](ova/ova-generate-artifact.md))
  - **Run Tests**: Procedure for executing tests to validate the OVA. ([ova-run-tests.md](ova/ova-run-tests.md))
