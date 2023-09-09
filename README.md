# PanOS Master Tshooter

PanOS Master Tshooter (MT) was designed for quick ad-hoc tshooting information for PanOS NGFWs connected to a Panorama.  The intention is to provide a quick way to get runtime information from NGFWs by sending the commands through Panorama.  Especially useful in an environment with many NGFWs connected to a single Panorama that have a lot of network and interface configurations (such as BGP, multi-vsys, multi-vr etc)

## Introduction

The `mt-cli.py` script is part of the PanOS Master Tshooter program, a set of tools to retrieve and manage information about NGFW routes, interfaces, virtual routers, and perform on-demand FIB (Forwarding Information Base) lookups. This script is designed to be used in a command-line environment.

The `mt-tools.py` script serves as a helper tool to prepare the database and perform initial setup steps required for the PanOS Master Tshooter project. It should be run before utilizing `mt-cli.py` and ensures that the required infrastructure is in place before using the primary command-line interface.

## Installation

Install requirements
```bash
python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

Build the initial database and load Panorama
```bash
python mt-tools.py -b -a
**Prompts for Panorama info**
```

Import the connected NGFWs
```bash
python mt-cli.py -i
```

Refresh (load initial) NGFW data
```bash
python mt-cli.py -r all
```

## Considerations
1. At this time only one Panorama (HA pair) is supported and standalone NGFWs are not supported at all.
2. All API calls are made through the Panorama so you do not need direct access to the NGFWs mgmt interface.
3. The API Key that is generated for the Panorama is stored in the SQLite database.  Protect it!
4. Recommend changing the `db_uri` variable in config.py to an absolute path where you would like it to reside.
5. Show commands like LLDP and BGP functions are on-demand at this time, so an API will be run per NGFW.
6. MT removes junk such as interfaces without zones or vrs, NGFWs in Panorama but not connected before entering it into the database.  You may find missing interfaces etc when using the print options.
7. Recommend using a read-only account on Panorama for security purposes.
8. Recommend NOT utilizing on central server, intention is to run on workstation.
9. Probably some bugs and vulns.  Please report and they will be addressed in the next version.

## MT-Tools Usage

To use `mt-tools.py`, open your terminal and navigate to the directory containing the script. You can execute various commands with the following syntax:

```bash
python mt-tools.py [options]
```

## MT-Tools Command-Line Options

Here are the available command-line options for `mt-tools.py`:

- `-b` or `--build-db`: Create an empty database at the URI specified in the configuration.
- `-a` or `--add-panorama`: Add a Panorama device to the database via a prompt.

## MT-Tools Examples

Here are some example commands to get you started with `mt-tools.py`:

- Build the database (creates an empty database):
  ```bash
  python mt-tools.py -b
  ```

- Add a Panorama device to the database:
  ```bash
  python mt-tools.py -a
  ```

Please note that running `mt-tools.py` is a prerequisite before using `mt-cli.py`. The `--build-db` option initializes the database, and the `--add-panorama` option allows you to add Panorama devices to the database as needed.

Ensure that you have configured the database URI and other relevant settings in `config.py` before running `mt-tools.py`. For detailed configuration instructions, refer to the project documentation or comments within the script itself.

## MT-CLI Usage
To use `mt-cli.py`, open your terminal and navigate to the directory containing the script. Then, you can execute various commands with the following syntax:

```bash
python mt-cli.py [options]
```

## MT-CLI Command-Line Options

Here are the available command-line options for `mt-cli.py`:

- `-i` or `--import-ngfws`: Import Panorama NGFWs (run before anything else).
- `-r` or `--refresh`: Refresh the database. Options include:
  - `routes`: Refresh routes (with optional filters for NGFW and virtual router).
  - `interfaces`: Refresh interfaces (with an optional filter for NGFW).
  - `ngfws`: Refresh NGFWs (with an optional filter for NGFW).
  - `all`: Refresh all data (non-functional).
- `-p` or `--print`: Choose what to print. Options include:
  - `routes`: Print routes (with optional filters for virtual router, NGFW, destination, and flags).
  - `interfaces`: Print interfaces (with optional filters for virtual router and NGFW).
  - `vrs`: Print virtual routers (with an optional filter for NGFW).
  - `ngfws`: Print NGFWs (with an optional filter for Panorama).
  - `pan`: Print Panorama devices.
- `-s` or `--show`: Choose what to 'show' on demand. Options include:
  - `lldp`: Show LLDP neighbors.
  - `bgp-peers`: Show BGP peers (with optional filters for NGFW and virtual router).
- `-f` or `--fib-lookup`: Perform FIB Lookup (requires specifying an IP address).
- `--ha-status`: Update HA (High Availability) status for NGFWs and Panorama.
- `--vr`: Virtual Router filter in various commands.
- `--ngfw`: NGFW filter for various commands.
- `--pan`: Panorama filter for various commands.
- - `--dst`: Destination filter for routes.
- - `--flag`: Comma-separated flags for routes.

## MT-CLI Examples

Here are some example commands to get you started:

- Import Panorama NGFWs:
  ```bash
  python mt-cli.py -i
  ```

- Refresh routes for a specific NGFW and virtual router:
  ```bash
  python mt-cli.py -r routes --ngfw <NGFW_NAME> --vr <VIRTUAL_ROUTER_NAME>
  ```

- Show LLDP neighbors for a specific NGFW:
  ```bash
  python mt-cli.py -s lldp --ngfw <NGFW_NAME>
  ```

- Perform FIB Lookup for an IP address:
  ```bash
  python mt-cli.py -f <IP_ADDRESS>
  ```

- Print routes with specific filters:
  ```bash
  python mt-cli.py -p routes --vr <VIRTUAL_ROUTER_NAME> --ngfw <NGFW_NAME> --dst <DESTINATION_FILTER> --flag <FLAGS>
  ```

- Update HA status for NGFWs:
  ```bash
  python mt-cli.py --ha-status
  ```

# Next Version (Future Release)

The next version of PanOS Master Tshooter (MT) is expected to bring new features and improvements to enhance its functionality and usability. Here's a sneak peek at what you can expect in the upcoming release:

## Bug Fixes and Enhancements

- Addressing and resolving any existing bugs and issues to ensure smoother operation.

## Multi Panorama Support

- Introduction of multi-Panorama support, allowing users to manage and troubleshoot multiple Panorama instances efficiently.

## Stand-Alone NGFW Support

- Expanded support for stand-alone Next-Generation Firewalls (NGFWs) in addition to Panorama devices.

## IPsec Tunnel Status

- Added functionality to retrieve and display IPsec tunnel status information for improved network monitoring.

## Enhanced Database

- Inclusion of more data points, such as LLDP neighbor information, into the database to provide a comprehensive view of network devices.

## PostgreSQL Support

- Support for PostgreSQL as an alternative database backend, offering users more flexibility in their choice of database management system.

## Web User Interface (WebUI)

- Development of a user-friendly web-based interface (WebUI) for easier interaction with the PanOS Master Tshooter tools. This will provide a more intuitive and visual way to manage and troubleshoot network devices.

## General Code Cleanup
- General cleanup and less lines of code.

Please stay tuned for the release of this next version, as it promises to deliver a more robust and feature-rich experience for network administrators and troubleshooters. Your feedback and suggestions are valuable as we continue to improve PanOS Master Tshooter to meet your network management needs.


# License

PanOS Master Tshooter is distributed under the MIT license.
