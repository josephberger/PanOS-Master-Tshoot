# PanOS Master Tshooter

PanOS Master Tshooter (MT) was designed for quick ad-hoc tshooting information for PanOS NGFWs connected to a Panorama.  The intention is to provide a quick way to get runtime information from NGFWs by sending the commands through Panorama or directly to an NGFW.  Especially useful in an environment with many NGFWs connected to a single Panorama that have a lot of network and interface configurations (such as BGP, multi-vsys, multi-vr etc).  Not intended to replace any of the Panorama or NGFW functionality, but to provide a quick way to get information without having to log into each NGFW individually.

## Version Changes

**Command Structure**
- Each command is now separated with its own flags (show, fib, import etc).  See below for examples.
- Each command has its own help menu.  Use `--help` to see the options for each command.
- Certain commands are not available depending on the state of the database.  For example, `show` is not available unless there are NGFWs present.

**More Information**
- NGFWs now have refresh time that is updated.
- Panoramas now show serial numbers.
- More verbose messaging for errors and success.

**Delete Panoramas or NGFWs**
- Panoramas or NGFWs can now be deleted from the database.  This will remove all associated information.

**Removal of mt-tools**
- Everything is now run through `mt-cli.py`
- `build-db` must be run before any other commands are available.
- If the database is available, command are then available to run and be seen in `--help`.  Note that `build-db` will not be available if the database has been built.

## Introduction

The `mt-cli.py` script is part of the PanOS Master Tshooter program, a set of tools to retrieve and manage information about NGFW routes, interfaces, virtual routers, and perform on-demand FIB (Forwarding Information Base) lookups. This script is designed to be used in a command-line environment.

## Installation

Install requirements (venv is optional)
```bash
python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

Build the initial database (must be done before any other commands are available)
```bash
python mt-cli.py build-db
```

Add a Panorama or NGFW (if hostname, username or password are not provided, user will be prompted)
```bash
python mt-cli.py add panorama -H <IP_ADDRESS>
```
```bash
python mt-cli.py add ngfw -H <IP_ADDRESS>
```

Import the connected NGFWs (if using Panorama)
```bash
python mt-cli.py import
```

Refresh (load initial) NGFW data (if no ngfw is specified, all NGFWs will be refreshed)
```bash
python mt-cli.py refresh --ngfw <NGFW_NAME>
```

## Considerations
1. All API calls are made through the Panorama so you do not need direct access to the NGFWs mgmt interface (unless its non-managed).
2. The API Key that is generated for the Panorama and non-managed NGFWs is stored in the SQLite database.  Protect it!
3. Recommend changing the `db_uri` variable in config.py to an absolute path where you would like it to reside.
4. MT removes junk such as interfaces without zones or vrs, NGFWs in Panorama but not connected before entering it into the database.  You may find missing interfaces etc when using the print options.
5. Recommend using a read-only account on Panorama/NGFWs for security purposes.
6. Recommend NOT utilizing on central server, intention is to run on workstation or jump host.
7. Currently only supports IPv4, IPv6 support coming soon.
8. For ease of use, most queries are based on hostnames once added/imported.  If you have multiple NGFWs with the same hostname, MT will add a `-1` to the back of the hostname.
9. Probably some bugs and vulns.  Please report and they will be addressed in the next version.

## MT-Tools Usage

To use `mt-tools.py`, open your terminal and navigate to the directory containing the script. You can execute various commands with the following syntax:

```bash
python mt-tools.py [options]
```

## MT-CLI Usage
To use `mt-cli.py`, open your terminal and navigate to the directory containing the script. Then, you can execute various commands with the following syntax:

```bash
python mt-cli.py [options]
```

## MT-CLI Command-Line Options

Here are the available command-line options for `mt-cli.py` (use --help for each command to see more details):

- `build-db`: Build the initial database. Must be run before any other commands are available if no db is present.
- `inventory`: Print inventory counts of the database.
- `add`: Add a Panorama or NGFW to the database.
- `delete`: Delete a Panorama or NGFW from the database.
- `import`: Import NGFWs connected to Panorama (run this before other operations if using Panorama).
- `refresh`: Refresh NGFW information (use with optional filters).
- `show`: Display routes, virtual routers, interfaces, NGFWs, Panorama details, LLDP neighbors, BGP peers.
- `fib`: Perform FIB Lookup for an IPv4 address.
- `update-ha`: Update HA (High Availability) status.

## MT-CLI Examples

Here are some example commands to get you started:

- Import Panorama NGFWs:
  ```bash
  python mt-cli.py import
  ```

- Refresh routes for a specific NGFW:
  ```bash
  python mt-cli.py refresh --ngfw <NGFW_NAME>
  ```

- Show LLDP neighbors for a specific NGFW on demand:
  ```bash
  python mt-cli.py show lldp --ngfw <NGFW_NAME> --on-demand
  ```

- Calculate FIB Lookup for an IP address:
  ```bash
  python mt-cli.py fib <IP_ADDRESS>
  ```

- Run test FIB Lookup for an IP address:
  ```bash
  python mt-cli.py fib <IP_ADDRESS> --on-demand
  ```

- Print routes with specific filters:
  ```bash
  python mt-cli.py show routes --vr <VIRTUAL_ROUTER_NAME> --ngfw <NGFW_NAME> --dst <DESTINATION_FILTER> --flag <FLAGS>
  ```

- Update HA status for NGFWs:
  ```bash
  python mt-cli.py update-ha
  ```

# License

PanOS Master Tshooter is distributed under the MIT license (see LICENSE file).

# Special Thanks

Special thanks to Kevin Steves for developing and maintaining [pan-python](https://github.com/kevinsteves/pan-python/tree/master)
