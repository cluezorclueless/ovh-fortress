# Deploy

Every command says where it runs. VPS = the server. Client = your own machine.

## 1. Build and test-attach (VPS)
    sudo apt-get install -y clang llvm libbpf-dev linux-libc-dev make bpftool
    sudo mkdir -p /opt/ovh-fortress && sudo cp -r xdp/* /opt/ovh-fortress/
    cd /opt/ovh-fortress && sudo make
    sudo ./load.sh on        # arms a 180 s auto-rollback
Open a NEW ssh session to prove you still have access, then:
    sudo ./load.sh confirm

## 2. Persist XDP across reboots (VPS)
    sudo cp systemd/fortress-xdp.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now fortress-xdp

## 3. nftables (VPS)
    sudo cp nftables.d/*.nft /etc/nftables.d/
    # /etc/nftables.conf must contain: include "/etc/nftables.d/*.nft"
    sudo nft -c -f /etc/nftables.conf && echo BOOT_OK
    sudo systemctl enable --now nftables
Gotcha: every .nft file must end with a trailing newline or the next include
fails to parse.

## 4. Kernel settings (VPS)
    sudo cp sysctl/*.conf /etc/sysctl.d/ && sudo sysctl --system
Also set `net.ipv4.ip_forward=1` if the box is a Tailscale exit node.

## 5. OVH Edge Network Firewall (OVH panel)
Network -> IP -> ... -> Edge Network Firewall. Priority order:
| Pri | Mode | Proto | Match |
|---|---|---|---|
| 0 | Authorise | TCP | dst 22 |
| 1 | Authorise | UDP | dst 41641 (Tailscale) |
| 2 | Authorise | ICMP | |
| 5 | Authorise | UDP | src 123 |
| 6 | Authorise | UDP | src 67 -> dst 68 |
| 7 | Authorise | TCP | established |
| 8 | Authorise | UDP | dst 32768-60999 (replies to your outbound UDP) |
| 19 | Refuse | IPv4 | all |
Do not authorise UDP 51820 unless you actually run WireGuard there.

## 6. Verify (VPS)
    sudo xdp-stats
    sudo nft list ruleset | grep -c counter
    tailscale status
