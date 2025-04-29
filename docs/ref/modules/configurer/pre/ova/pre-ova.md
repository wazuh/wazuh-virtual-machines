# OVA Pre Configurer

The **OVA Pre Configurer** performs specific tasks that create and prepare a virtual machine with **Amazon Linux 2023** as the operating system.

> ⚠️ This module is intended to be part of the **Build OVA workflow** developed in the `wazuh-virtual-machines` repository so its separate use is possible but it might require adaptation to work properly.

The tasks that this module executes are listed below and then each task will be described:

- Dependencies installation.
- Generation of the base Vagrant box.
- Deployment of the VM.
- Preparation of the VM.

## Dependencies installation

This submodule installs the following dependencies:

- `kernel-devel`
- `kernel-headers`
- `dkms`
- `elfutils-libelf-devel`
- `gcc`
- `make`
- `perl`
- `python3-pip`
- `git`
- `Development Tools group`
- `Virtual Box`
- `vagrant`

It also excludes the `kernel-devel` and `kernel-headers` from updating once the required version is installed.

## Generation of the base Vagrant box

This submodule uses the `generate_base_box.py` and `setup.py` scripts to generate a Vagrant `.box` file with the latest version of Amazon Linux 2023. It also performs some configurations to make the Vagrant box accessible.

## Deployment of the VM

This submodule makes use of the Vagrant box created in the previous step and adds it to the list of boxes to use. It then deploys a VM making use of the existing `Vagrantfile` in the repository.

## Preparation of the VM

This submodule connects from the host to the VM deployed in the previous step and prepares the VM for the execution of the **OVA Post Configurer**.
For this, it installs `python3-pip` and `hatch` on the VM.
In addition, it deletes the residual files from the creation of the Vagrant box from the previous **Generation of the base Vagrant box** submodule.
Finally, it copies the `wazuh-virtual-machines` repository from the host machine to the deployed VM in `/tmp`.

## Considerations

The **OVA Pre Configurer** is designed to be executed in a **local machine only**. In addition, this machine **must** support virtualization.

## Execution

This module is desgined to run alongside the **OVA Post Configurer**, **not individually**. By the design constraints of the OVA build, you can run this module unilaterally, which would result in having a VM deployed with Amazon Linux 2023 and the `wazuh-virtual-machines` repository cloned in `/tmp`.

The module can be executed by running this command:

```bash
hatch run dev-ova-pre-configurer:run
```
