"""VM setup, installation, and provisioning — re-export facade.

The implementation lives in the submodules; this file re-exports every
public and test-used symbol so that existing import paths
(``from winbox.setup.installer import X``) continue to work.
"""

from winbox.setup.installer.prereqs import (  # noqa: F401
    PROFILE_GATED_TOOLS,
    REQUIRED_TOOLS,
    TOOL_PACKAGES,
    VIRTIOFSD_PATHS,
    _find_mkisofs,
    _tool_required,
    check_prereqs,
    copy_setup_files,
    create_directories,
    ensure_default_network,
    generate_ssh_keypair,
    grant_libvirt_access,
)
from winbox.setup.installer.downloads import (  # noqa: F401
    OPENSSH_URL,
    OPENSSH_ZIP,
    PYTHON_EMBED_URL,
    PYTHON_EMBED_ZIP,
    PYTHON_EXE,
    PYTHON_URL,
    RUNEX_EXE,
    RUNEX_SHA256,
    RUNEX_URL,
    SPICE_TOOLS_EXE,
    SPICE_TOOLS_SHA256,
    SPICE_TOOLS_URL,
    VIRTIOFS_EXE,
    WINFSP_MSI,
    WINFSP_URL,
    X64DBG_URL,
    X64DBG_ZIP,
    _sha256,
    _virtiofs_cache_path,
    _virtiofs_iso_member,
    download_openssh,
    download_python,
    download_python_embed,
    download_runex,
    download_spice_tools,
    download_virtio_iso,
    download_winfsp,
    download_x64dbg,
    extract_virtiofs,
)
from winbox.setup.installer.unattend import (  # noqa: F401
    _LABCONFIG_KEYS,
    _disk_partitions_block,
    _labconfig_block,
    _product_key_block,
    _specialize_deploy_block,
    build_unattend_image,
    create_disk,
    run_virt_install,
)
from winbox.setup.installer.provision import (  # noqa: F401
    BOOTSTRAP_LOG,
    PROVISION_SENTINEL,
    _SYSTEM_HIVE,
    _disable_defender_offline,
    _guestfish,
    _settle_firstlogon_boot,
    boot_for_provisioning,
    provision_vm_disk,
)
from winbox.setup.installer.finalize import (  # noqa: F401
    _shutdown_and_wait,
    _verify_provisioning,
    _verify_python,
    _verify_runex,
    attach_default_filter,
    create_clean_snapshot,
    register_nwfilter,
)

from winbox.defender import DEFENDER_OFF_SYSTEM_REG as _DEFENDER_OFF_SYSTEM_REG  # noqa: F401
