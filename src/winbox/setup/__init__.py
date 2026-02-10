"""Setup pipeline — installer, ISO downloader."""

from winbox.setup.installer import (
    check_prereqs,
    create_directories,
    ensure_default_network,
    grant_libvirt_access,
    download_virtio_iso,
    generate_ssh_keypair,
    copy_setup_files,
    build_unattend_image,
    create_disk,
    run_virt_install,
    provision_vm_disk,
    boot_for_provisioning,
    create_clean_snapshot,
)
from winbox.setup.iso import ISO_FILENAME, download_iso

__all__ = [
    "check_prereqs",
    "create_directories",
    "ensure_default_network",
    "grant_libvirt_access",
    "download_virtio_iso",
    "generate_ssh_keypair",
    "copy_setup_files",
    "build_unattend_image",
    "create_disk",
    "run_virt_install",
    "provision_vm_disk",
    "boot_for_provisioning",
    "create_clean_snapshot",
    "ISO_FILENAME",
    "download_iso",
]
