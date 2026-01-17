# GameStream IPv6 Forwarder
Current versions of GeForce Experience do not listen on IPv6 for connections from GameStream clients by default.

Running this forwarding service on the GameStream host allows Moonlight clients to access it over IPv6. It also automatically configures capable IPv6 firewalls to allow GameStream traffic to your PC from the Internet.

This tool can allow Moonlight access to multiple PCs behind a single router if your server and client both have IPv6 connectivity.

# Windows Instructions
1. Download MSI package from the [GitHub Releases](https://github.com/moonlight-stream/GS-IPv6-Forwarder/releases) page.
2. Install the package on your gaming PC. The service will run automatically in the background.
3. Give it a try! Connect via Moonlight using an IPv6 address or host name.

# Linux/Ubuntu Instructions

## Building from Source

### Prerequisites
Install the required dependencies:
```bash
sudo apt-get update
sudo apt-get install build-essential libminiupnpc-dev
```

### Building
```bash
make
```

### Installing
```bash
sudo make install
```

This will install the `gsv6fwd` binary to `/usr/local/bin/`.

### Running

Run in foreground mode:
```bash
./gsv6fwd
```

Run as a daemon (background):
```bash
sudo ./gsv6fwd -d
```

### Setting up as a systemd service

Generate and install a systemd service file:
```bash
make systemd-service
sudo cp gsv6fwd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable gsv6fwd
sudo systemctl start gsv6fwd
```

Check service status:
```bash
sudo systemctl status gsv6fwd
```

### Command Line Options
- `-d, --daemon` - Run as a background daemon
- `-h, --help` - Show help message

# Troubleshooting
1. Make sure that your router and PC firewalls are configured to allow IPv6 traffic on the [GameStream ports](https://github.com/moonlight-stream/moonlight-docs/wiki/Setup-Guide#other-firewall-software). This tool will automatically create firewall exceptions on routers that support PCP or UPnP IPv6 firewall control, but you will need to do this manually on some routers.
2. Make sure that both your gaming PC and Moonlight client device have IPv6 connectivity on their active networks using a site like http://test-ipv6.com/
3. On Linux, logs are written to `/var/log/gsv6fwd/` when running as a daemon, or to stdout when running in foreground mode.
