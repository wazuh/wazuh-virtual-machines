#!/bin/bash

# AL2023 Vagrant base box generator
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation."

set -euxo pipefail

# Constants for version and filenames
AL2023_VERSION="latest"

if [ "${AL2023_VERSION}" == "latest" ]; then
    AL2023_VERSION=$(curl -I https://cdn.amazonlinux.com/al2023/os-images/latest/ | grep -i location | awk -F'/' '{print $(NF-1)}')
fi

OVA_FILENAME="al2023-vmware_esx-${AL2023_VERSION}-kernel-6.1-x86_64.xfs.gpt.ova"
VMDK_FILENAME=""  # Will be determined dynamically after extraction
AL2023_OVA_OUTPUT="al2023.ova"
# Temporary directories for raw, mount, and VDI files
RAW_DIR="$(mktemp -d -t al2023_raw_XXXXXXXX)"
MOUNT_DIR="$(mktemp -d -t al2023_mnt_XXXXXXXX)"
VDI_DIR="$(mktemp -d -t al2023_vdi_XXXXXXXX)"

cleanup() {
    # Cleanup temporary directories and unmount if necessary
    umount "${MOUNT_DIR}/dev" || true
    umount "${MOUNT_DIR}/proc" || true
    umount "${MOUNT_DIR}/sys" || true
    umount "${MOUNT_DIR}" || true
    rm -rf "${RAW_DIR}" "${MOUNT_DIR}" "${VDI_DIR}"
    vboxmanage unregistervm al2023 --delete || true
}

trap cleanup EXIT

check_dependencies() {
    for cmd in vboxmanage wget tar chroot; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "$cmd is required but not installed. Exiting."
            exit 1
        fi
    done
}

download_and_extract_ova() {
    # Check if VMDK already exists
    local existing_vmdk=$(find . -maxdepth 1 -name "*.vmdk" -type f | head -n 1)
    if [ -n "${existing_vmdk}" ]; then
        VMDK_FILENAME=$(basename "${existing_vmdk}")
        return
    fi
    
    # Download and extract OVA
    wget "https://cdn.amazonlinux.com/al2023/os-images/${AL2023_VERSION}/vmware/${OVA_FILENAME}"
    tar xvf "${OVA_FILENAME}"
    
    # Find the extracted VMDK file
    existing_vmdk=$(find . -maxdepth 1 -name "*.vmdk" -type f | head -n 1)
    if [ -z "${existing_vmdk}" ]; then
        echo "Error: No VMDK file found after extracting OVA"
        exit 1
    fi
    VMDK_FILENAME=$(basename "${existing_vmdk}")
}

convert_vmdk_to_raw() {
    vboxmanage clonemedium "${VMDK_FILENAME}" "${RAW_DIR}/al2023.raw" --format RAW
    vboxmanage closemedium "${VMDK_FILENAME}"
    vboxmanage closemedium "${RAW_DIR}/al2023.raw"
}

mount_and_setup_image() {
    mount -o loop,offset=12582912 "${RAW_DIR}/al2023.raw" "${MOUNT_DIR}"
    cp -a setup.sh "${MOUNT_DIR}/."
    mount -o bind /dev "${MOUNT_DIR}/dev"
    mount -o bind /proc "${MOUNT_DIR}/proc"
    mount -o bind /sys "${MOUNT_DIR}/sys"
    chroot "${MOUNT_DIR}" /setup.sh
    umount "${MOUNT_DIR}/dev"
    umount "${MOUNT_DIR}/proc"
    umount "${MOUNT_DIR}/sys"
    umount "${MOUNT_DIR}"
}

convert_raw_to_vdi() {
    vboxmanage convertfromraw "${RAW_DIR}/al2023.raw" "${VDI_DIR}/al2023.vdi" --format VDI
}

create_virtualbox_vm() {
    vboxmanage createvm --name al2023 --ostype Linux26_64 --register
    vboxmanage modifyvm al2023 --memory 1024 --vram 16 --audio none
    vboxmanage storagectl al2023 --name IDE --add ide
    vboxmanage storagectl al2023 --name SATA --add sata --portcount 1
    vboxmanage storageattach al2023 --storagectl IDE --port 1 --device 0 --type dvddrive --medium emptydrive
    vboxmanage storageattach al2023 --storagectl SATA --port 0 --device 0 --type hdd --medium "${VDI_DIR}/al2023.vdi"
}

package_vagrant_box() {
    vagrant package --base al2023 --output al2023.box
    vboxmanage export al2023 -o "${AL2023_OVA_OUTPUT}"
}

# Main script execution
check_dependencies
download_and_extract_ova
convert_vmdk_to_raw
mount_and_setup_image
convert_raw_to_vdi
create_virtualbox_vm
package_vagrant_box