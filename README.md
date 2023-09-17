# PanOS Master Tshooter

PanOS Master Tshooter (MT) was designed for quick ad-hoc tshooting information for PanOS NGFWs connected to a Panorama.  The intention is to provide a quick way to get runtime information from NGFWs by sending the commands through Panorama.  Especially useful in an environment with many NGFWs connected to a single Panorama that have a lot of network and interface configurations (such as BGP, multi-vsys, multi-vr etc)

## Version Changes

**Multi Panorama Support**
Now supports more than one Panorama (or HA pair).  Adding a Panorama using `mt-tools` is now done with the `-p` or `--p` flags.

**Stand Alone Firewall Support**
Firewalls (and HA pairs) now supported with the `mt-tools`, add one with the `-n` or `--ngfw` flags.

**Refresh Changes**
Refresh is now performed by `-r` or `--refresh` and accepts only an `--ngfw` which refreshes everything about an NGFW.  This was done since the API commands are not vsys or vr specific.  Note that NOT using the `--ngfw` filter will result in refreshing all NGFWs (Panorama connected or stand alone)

**Only Show Commands**
The `print` command via `-p` or `--print` is no longer available.  `-s` or `--show` now performs the same functionality but with the optional `--on-demand` flag, the information is pulled directly from the device vs the database.  (see supported "On Deman" commands)

**Fib Calculation**
Fib lookup is now done through a calculation based on routes and interfaces.  `--on-deman` can be used in conjunction to bypass the calculation and use the API instead.  API functionality can be especially helpful in environments with policy based forwarding.

**Supported On Demand Commands**
Some commands now feature 'on-deman' which executes an API command for real time stats
- fib-lookup
- show
  - bgp-peers
  - interfaces
  - lldp

Showing Panorama and NGFW will never be included since they are semi-static entries.  Routes and VRs MAY be included in the future but not likley (use `--refresh` to get new items).

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

Build the initial database and load Panorama (or stand-along NGFW)
```bash
python mt-tools.py -b -p (or -n)
**Prompts for Panorama info**
```

Import the connected NGFWs (if using Panorama)
```bash
python mt-cli.py -i
```

Refresh (load initial) NGFW data
```bash
python mt-cli.py -r
```

## Considerations
1. All API calls are made through the Panorama so you do not need direct access to the NGFWs mgmt interface (unless its stand-alone).
2. The API Key that is generated for the Panorama and stand-alone NGFWs is stored in the SQLite database.  Protect it!
3. Recommend changing the `db_uri` variable in config.py to an absolute path where you would like it to reside.
4. MT removes junk such as interfaces without zones or vrs, NGFWs in Panorama but not connected before entering it into the database.  You may find missing interfaces etc when using the print options.
5. Recommend using a read-only account on Panorama for security purposes.
6. Recommend NOT utilizing on central server, intention is to run on workstation or jump host.
7. Probably some bugs and vulns.  Please report and they will be addressed in the next version.

## MT-Tools Usage

To use `mt-tools.py`, open your terminal and navigate to the directory containing the script. You can execute various commands with the following syntax:

```bash
python mt-tools.py [options]
```

## MT-Tools Command-Line Options

Here are the available command-line options for `mt-tools.py`:

- `-b` or `--build-db`: Create an empty database at the URI specified in the configuration.
- `-p` or `--add-panorama`: Add a Panorama device to the database via a prompt.
- `-n` or `--add-ngfw`: Add a NGFW device to the database via a prompt.

Some extra flags can be used such as `--ip-address`, `--username` and `--password` to skip the prompt (password not recomended).

## MT-Tools Examples

Here are some example commands to get you started with `mt-tools.py`:

- Build the database (creates an empty database):
  ```bash
  python mt-tools.py -b
  ```

- Add a Panorama device to the database:
  ```bash
  python mt-tools.py -p
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
- `-r` or `--refresh`: Refresh the database (use `--ngfw` to select a single NGFW)
- `-s` or `--show`: Choose what to 'show' on demand. Options include:
  - `routes`: Show routes (with optional filters for virtual router, NGFW, destination, and flags).
    - `--dst`: Destination filter for routes.
    - `--flag`: Comma-separated flags for routes.
  - `interfaces`: Print interfaces (with optional filters for virtual router and NGFW).
  - `vrs`: Print virtual routers (with an optional filter for NGFW).
  - `ngfws`: Print NGFWs (with an optional filter for Panorama).
  - `pan`: Print Panorama devices.
  - `lldp`: Show LLDP neighbors.
  - `bgp-peers`: Show BGP peers (with optional filters for NGFW and virtual router).
- `-f` or `--fib-lookup`: Perform FIB Lookup (requires specifying an IP address).
- `--ha-status`: Update HA (High Availability) status for NGFWs and Panorama.
- `--vr`: Virtual Router filter in various commands.
- `--ngfw`: NGFW filter for various commands.
- `--pan`: Panorama filter for various commands.
- `--on-demand`: Get the infomration directly from the device vs database (runs commands on the firewall for some show commands and fib lookup)


## MT-CLI Examples

Here are some example commands to get you started:

- Import Panorama NGFWs:
  ```bash
  python mt-cli.py -i
  ```

- Refresh routes for a specific NGFW:
  ```bash
  python mt-cli.py -r --ngfw <NGFW_NAME>
  ```

- Show LLDP neighbors for a specific NGFW on demand:
  ```bash
  python mt-cli.py -s lldp --ngfw <NGFW_NAME> --on-demand
  ```

- Calculate FIB Lookup for an IP address:
  ```bash
  python mt-cli.py -f <IP_ADDRESS>
  ```

- Run test FIB Lookup for an IP address:
  ```bash
  python mt-cli.py -f <IP_ADDRESS> --on-demand
  ```

- Print routes with specific filters:
  ```bash
  python mt-cli.py -s routes --vr <VIRTUAL_ROUTER_NAME> --ngfw <NGFW_NAME> --dst <DESTINATION_FILTER> --flag <FLAGS>
  ```

- Update HA status for NGFWs:
  ```bash
  python mt-cli.py --ha-status
  ```

# Future Versions

**Bug Fixes and Enhancements**

- Addressing and resolving any existing bugs and issues to ensure smoother operation.

**IPsec Tunnel Status**

- Added functionality to retrieve and display IPsec tunnel status information for improved network monitoring.

**Web User Interface (WebUI)**

- Development of a user-friendly web-based interface (WebUI) for easier interaction with the PanOS Master Tshooter tools.
- PSQL database vs sqlite

**General Code Cleanup**
- General cleanup and less lines of code.


# License

PanOS Master Tshooter is distributed under the MIT license (see LICENSE file).

# Special Thanks
Special thanks to Kevin Steves for developing and maintaining [pan-python](https://github.com/kevinsteves/pan-python/tree/master)
