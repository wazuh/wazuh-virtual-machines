#!/bin/bash

# Amazon Linux 2023 vagrant box construction, using an Amazon supplied VMDK
# disk image as a base. This script runs inside of a mounted Amazon Linux 2023
# VMDK disk image, and sets up the vagrant related changes.

# Greg Bailey <gbailey@lxpro.com>
# November 25, 2023

set -eux

# The image doesn't have any resolvers specified
configure_dns() {
    rm -f /etc/resolv.conf
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
}

# Set up wazuh-user
setup_user() {
    useradd -m -s /bin/bash wazuh-user
    echo "wazuh-user:wazuh" | chpasswd

    mkdir -p /home/wazuh-user/.ssh
    wget -nv https://raw.githubusercontent.com/hashicorp/vagrant/main/keys/vagrant.pub -O /home/wazuh-user/.ssh/authorized_keys
    chmod 600 /home/wazuh-user/.ssh/authorized_keys
    chmod 700 /home/wazuh-user/.ssh
    chown -R wazuh-user:wazuh-user /home/wazuh-user

    echo 'wazuh-user ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/wazuh-user
    chmod 440 /etc/sudoers.d/wazuh-user
}

# Install legacy network-scripts required by Vagrant and git required to generate the OVA
install_dependencies() {
    yum -y install network-scripts git
}

# Install the VirtualBox guest additions
install_guest_additions() {
    yum -y install gcc elfutils-libelf-devel kernel-devel libX11 libXt libXext libXmu

    dnf remove $(dnf repoquery --installonly --latest-limit=-1)

    KERNEL_VERSION=$(ls /lib/modules)
    VIRTUALBOX_VERSION=$(wget -q http://download.virtualbox.org/virtualbox/LATEST.TXT -O -)

    wget -nv https://download.virtualbox.org/virtualbox/${VIRTUALBOX_VERSION}/VBoxGuestAdditions_${VIRTUALBOX_VERSION}.iso -O /root/VBoxGuestAdditions.iso
    mount -o ro,loop /root/VBoxGuestAdditions.iso /mnt
    sh /mnt/VBoxLinuxAdditions.run || true  # Allow script to proceed despite potential errors
    umount /mnt
    rm -f /root/VBoxGuestAdditions.iso

    # Run VBox guest additions setup for the Amazon provided kernel
    /etc/kernel/postinst.d/vboxadd ${KERNEL_VERSION}
    /sbin/depmod ${KERNEL_VERSION}

    # Try to load modules
    /sbin/modprobe vboxguest 2>/dev/null || echo "⚠ vboxguest not loaded yet (will load on boot)"
    /sbin/modprobe vboxsf 2>/dev/null || echo "⚠ vboxsf not loaded yet (will load on boot)"
    /sbin/modprobe vboxvideo 2>/dev/null || echo "⚠ vboxvideo not loaded yet (will load on boot)"

    # Validation
    if lsmod | grep -q vboxguest; then
        echo "✓ Guest Additions modules loaded successfully"
    else
        echo "⚠ Guest Additions modules not loaded in current session"
        echo "  This is normal when building in chroot environment"
        echo "  Modules will load on next boot"

        if [ -f "/lib/modules/${KERNEL_VERSION}/misc/vboxguest.ko" ]; then
            echo "✓ vboxguest.ko exists in /lib/modules/${KERNEL_VERSION}/misc/"
        else
            echo "✗ ERROR: vboxguest.ko not found!"
            exit 1
        fi

        if [ -f "/etc/init.d/vboxadd" ] || [ -f "/usr/lib/systemd/system/vboxadd.service" ]; then
            echo "✓ VBoxAdd service files exist"
        else
            echo "✗ ERROR: VBoxAdd service not installed!"
            exit 1
        fi
    fi

    # ============================================
    # NEW: FORCE ENABLE SERVICES
    # ============================================

    # Enable Guest Additions services
    if [ -f "/usr/lib/systemd/system/vboxadd.service" ]; then
        # Create symlinks manually to ensure they are executed
        mkdir -p /etc/systemd/system/multi-user.target.wants
        ln -sf /usr/lib/systemd/system/vboxadd.service /etc/systemd/system/multi-user.target.wants/vboxadd.service
        ln -sf /usr/lib/systemd/system/vboxadd-service.service /etc/systemd/system/multi-user.target.wants/vboxadd-service.service
        echo "✓ VBoxAdd services enabled via symlinks"
    fi

    # Add to rc.local as fallback
    if [ ! -f /etc/rc.d/rc.local ]; then
        touch /etc/rc.d/rc.local
        chmod +x /etc/rc.d/rc.local
    fi

    # Add command to load modules on boot
    cat >> /etc/rc.d/rc.local << 'EOF'
# VirtualBox Guest Additions - ensure modules are loaded
if [ -f /etc/init.d/vboxadd ]; then
    /etc/init.d/vboxadd start || true
fi
EOF
    chmod +x /etc/rc.d/rc.local

    # Enable rc-local.service
    if [ -f /usr/lib/systemd/system/rc-local.service ]; then
        ln -sf /usr/lib/systemd/system/rc-local.service /etc/systemd/system/multi-user.target.wants/rc-local.service
    fi

    echo "✓ Guest Additions installation validated and boot scripts configured"
}

# Enable SSH password authentication
configure_ssh() {
    # Modify the main config
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

    # Create an explicit override file
    mkdir -p /etc/ssh/sshd_config.d/
    cat > /etc/ssh/sshd_config.d/50-vagrant-password-auth.conf << 'EOF'
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
EOF

    chmod 600 /etc/ssh/sshd_config.d/50-vagrant-password-auth.conf
    systemctl restart sshd
}


# Clean up temporary files and free up space
cleanup() {
    yum clean all
    rm -rf /var/cache/yum/*

    rm -f /etc/resolv.conf

    rm -f /setup.sh

    for i in $(seq 2); do
        sync
        dd if=/dev/zero of=/zero$i bs=1M || true
        sleep 1
        rm -f /zero$i
    done
}

# Main script execution
configure_dns
setup_user
install_dependencies
install_guest_additions
configure_ssh
cleanup