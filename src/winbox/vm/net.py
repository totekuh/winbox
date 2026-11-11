"""VM networking mixin — NIC discovery, IP lookup, link-state control."""

from __future__ import annotations

from winbox.vm.virsh import _parse_domiflist, _virsh_err, virsh_run


class VMNetMixin:
    """Networking methods inherited by the VM class."""

    name: str

    def ip(self) -> str | None:
        """Return the VM's IPv4 address on the libvirt default network."""
        result = virsh_run("domifaddr", self.name, check=False)
        if result.returncode != 0:
            return None
        target_iface = self.interface()
        current_iface: str | None = None
        first_seen_ip: str | None = None
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("Name") or stripped.startswith("-"):
                continue
            parts = stripped.split()
            if len(parts) >= 4 and not parts[0].startswith("0x") and "ipv4" in parts:
                current_iface = parts[0]
            if "ipv4" in parts:
                for part in parts:
                    if "/" in part and "." in part:
                        ip_addr = part.split("/")[0]
                        if first_seen_ip is None:
                            first_seen_ip = ip_addr
                        if target_iface and current_iface == target_iface:
                            return ip_addr
        if target_iface is None:
            return first_seen_ip
        return None

    def nics(self, *, inactive: bool = False) -> list[tuple[str | None, str]]:
        """Every NIC as ``(host tap name, MAC)``, in domain-XML order."""
        args = ["domiflist", self.name]
        if inactive:
            args.append("--inactive")
        result = virsh_run(*args, check=False)
        if result.returncode != 0:
            return []
        return _parse_domiflist(result.stdout)

    def nic_macs(self, *, inactive: bool = False) -> list[str]:
        """Every NIC's MAC address. ``[]`` on failure."""
        return [mac for _tap, mac in self.nics(inactive=inactive)]

    def interface(self) -> str | None:
        """Get the VM's network interface name (e.g. 'vnet0')."""
        for tap, _mac in self.nics():
            if tap:
                return tap
        return None

    def net_set_link(
        self, state: str, *, live: bool = True, config: bool = True,
    ) -> None:
        """Set the link state ('up' or 'down') of every NIC, persistently."""
        if state not in ("up", "down"):
            raise ValueError(f"link state must be 'up' or 'down', got {state!r}")
        if not live and not config:
            raise ValueError("at least one of live/config must be True")

        if config:
            macs = self.nic_macs(inactive=True)
            if not macs:
                raise RuntimeError(
                    f"cannot persist link {state}: no network interface found in "
                    f"{self.name}'s persistent config (virsh domiflist --inactive)"
                )
            for mac in macs:
                result = virsh_run(
                    "domif-setlink", self.name, mac, state, "--config", check=False,
                )
                if result.returncode != 0:
                    raise RuntimeError(
                        f"link {state} NOT applied: persistent write for {mac} "
                        f"failed: {_virsh_err(result)}"
                    )

        if live:
            prefix = (
                f"link {state} persisted for next boot but" if config
                else f"link {state}"
            )
            macs = self.nic_macs()
            if not macs:
                raise RuntimeError(
                    f"{prefix} NOT applied live: no network interface found"
                )
            for mac in macs:
                result = virsh_run(
                    "domif-setlink", self.name, mac, state, check=False,
                )
                if result.returncode != 0:
                    raise RuntimeError(
                        f"{prefix} NOT applied live ({mac}): {_virsh_err(result)}"
                    )

    def net_link_states(
        self, *, config: bool = False,
    ) -> list[tuple[str, str | None]]:
        """Per-NIC ``(MAC, 'up' | 'down' | None)`` for a single scope."""
        states: list[tuple[str, str | None]] = []
        for mac in self.nic_macs(inactive=config):
            args = ["domif-getlink", self.name, mac]
            if config:
                args.append("--config")
            result = virsh_run(*args, check=False)
            if result.returncode != 0:
                states.append((mac, None))
                continue
            words = result.stdout.split()
            state = next((w for w in words if w in ("up", "down")), None)
            states.append((mac, state))
        return states

    def net_link_state(self, *, config: bool = False) -> str | None:
        """Aggregate link state across every NIC: 'up', 'down' or None."""
        states = self.net_link_states(config=config)
        if not states or any(s is None for _mac, s in states):
            return None
        return "up" if any(s == "up" for _mac, s in states) else "down"
