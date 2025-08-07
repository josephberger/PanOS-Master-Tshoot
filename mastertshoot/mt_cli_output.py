# mastertshoot/mt_cli_output.py

import csv
import logging
import sys # Needed for sys.exit in _confirm_on_demand_scope, but that method will remain in mt-cli for now.

# Import constants from the new central constants file
from mastertshoot.mt_constants import *

class MTCLIOutput:
    """
    Handles all command-line interface output formatting, including
    tabular display, detailed views, and CSV export.
    """

    def __init__(self):
        logging.debug("MTCLIOutput initialized.")

    def print_results(self, headers: dict, results=None, message=None):
        """
        Formats and prints results in a tabular format.

        Args:
            headers (dict): Dictionary mapping display header names (str) to data keys (str).
                            Example: {"NGFW": "ngfw", "Virtual Router": "virtual_router"}
            results (list[dict], optional): List of dictionaries, where each dictionary is a row
                                             containing data keyed by the values in `headers`. Defaults to None.
            message (list[str], optional): List of strings to print after the table. Defaults to None.
        """
        # --- Check if results is None or empty ---
        if not results:
            if message:
                print() # Add a newline before messages
                print("\n".join(message))
            else:
                print("No results found.") # Inform user if no results and no message
            print() # Add a final newline for spacing
            return # Exit the function early

        # --- Calculate Column Widths ---
        def calculate_max_widths():
            max_widths = {}
            for header, key in headers.items():
                header_width = len(str(header))
                # Ensure key exists in results before accessing, provide default length 0 if not
                # Also handle potential None values in results
                value_width = max((len(str(r.get(key, ''))) for r in results if r is not None), default=0)
                max_widths[header] = max(header_width, value_width)
            return max_widths

        # --- Format Strings ---
        def create_format_string(max_widths):
            spacing = 2
            return " ".join(f"{{:<{width+spacing}}}" for width in max_widths.values())

        # --- Print Header ---
        def print_header_row(format_string):
            header_str = format_string.format(*headers.keys())
            print(header_str)

        # --- Print Data Rows ---
        def print_data_rows(format_string):
            for r in results:
                if r is None: # Skip if a result row is None
                    continue
                # Ensure all keys from headers are present in the result dictionary 'r'
                # Provide a default value (e.g., 'N/A' or '') if a key is missing
                result_values = [r.get(key, 'N/A') for key in headers.values()]
                result_str = format_string.format(*result_values)
                print(result_str)

        # --- Execution ---
        max_widths = calculate_max_widths()
        format_string = create_format_string(max_widths)

        print_header_row(format_string)
        print_data_rows(format_string)

        # --- Print Optional Messages ---
        if message:
            print() # Add a newline before messages
            print("\n".join(message))

        print() # Add a final newline for spacing

    def print_interfaces_v6(self, results, message):
        """
        Handles the custom multi-line printing for IPv6 enabled interfaces.

        Args:
            results (list[dict]): List of dictionaries, each representing an interface
                                  and containing 'ipv6_address_list'.
            message (list[str]): List of messages from the controller to print afterwards.
        """
        if not results:
            print() # Newline for spacing
            if message:
                print("\n".join(message))
            else:
                # Provide specific message if controller didn't
                print("No IPv6 enabled interfaces found matching criteria.")
            print() # Final newline
            return

        # --- Custom Printing Logic ---
        col_padding = 2 # Spaces between columns
        max_ngfw_width = max(len(HDR_NGFW), max((len(r.get(KEY_NGFW, '')) for r in results), default=0))
        max_vr_width = max(len(HDR_VR), max((len(r.get(KEY_VR, '')) for r in results), default=0))
        max_name_width = max(len(HDR_NAME), max((len(r.get(KEY_NAME, '')) for r in results), default=0))
        max_tag_width = max(len(HDR_TAG), max((len(str(r.get(KEY_TAG, ''))) for r in results), default=0))
        max_zone_width = max(len(HDR_ZONE), max((len(r.get(KEY_ZONE, '')) for r in results), default=0))

        # Print Header Row
        header_format = (
            f"{{:<{max_ngfw_width + col_padding}}}"
            f"{{:<{max_vr_width + col_padding}}}"
            f"{{:<{max_name_width + col_padding}}}"
            f"{{:<{max_tag_width + col_padding}}}"
            f"{{:<{max_zone_width + col_padding}}}"
            f"{{}}"
        )
        print(header_format.format(HDR_NGFW, HDR_VR, HDR_NAME, HDR_TAG, HDR_ZONE, HDR_IPV6_ADDRESSES))

        # Print Data Rows
        base_row_format = (
            f"{{:<{max_ngfw_width + col_padding}}}"
            f"{{:<{max_vr_width + col_padding}}}"
            f"{{:<{max_name_width + col_padding}}}"
            f"{{:<{max_tag_width + col_padding}}}"
            f"{{:<{max_zone_width + col_padding}}}"
        )

        indent_length = (max_ngfw_width + col_padding +
                         max_vr_width + col_padding +
                         max_name_width + col_padding +
                         max_tag_width + col_padding +
                         max_zone_width + col_padding)
        indent = " " * indent_length

        for r in results:
            ngfw = r.get(KEY_NGFW, 'N/A')
            vr = r.get(KEY_VR, 'N/A')
            name = r.get(KEY_NAME, 'N/A')
            tag = str(r.get(KEY_TAG, 'N/A'))
            zone = r.get(KEY_ZONE, 'N/A')
            ipv6_list = r.get(KEY_IPV6_ADDRESS_LIST, [])

            first_line = True
            if ipv6_list:
                for ipv6_addr in ipv6_list:
                    if first_line:
                        print(base_row_format.format(ngfw, vr, name, tag, zone) + f"{ipv6_addr}")
                        first_line = False
                    else:
                        print(f"{indent}{ipv6_addr}")
            else:
                print(base_row_format.format(ngfw, vr, name, tag, zone) + "(No IPv6 Addresses Found)")

        # Print any controller messages after the table
        if message:
            print("\n")
            print("\n".join(message))

        print() # Final newline for spacing

    def print_ngfw_detail_results(self, results=None, message=None):
        """
        Formats and prints detailed NGFW information in a per-device attribute-value list.

        Args:
            results (list[dict], optional): List of dictionaries, where each dictionary is
                                             an NGFW's data from controller._format_ngfw_result.
            message (list[str], optional): List of strings to print after all devices.
        """
        if not results:
            if message:
                print()
                print("\n".join(message))
            else:
                print("No NGFWs found to display details for.")
            print()
            return

        # Define the order and labels for attributes
        attributes_to_print = [
            (LBL_SERIAL, KEY_SERIAL),
            (LBL_IP_ADDRESS, KEY_IP_ADDRESS),
            (LBL_IPV6_ADDRESS, KEY_IPV6_ADDRESS_DETAIL),
            (LBL_MAC_ADDRESS, KEY_MAC),
            (LBL_MODEL, KEY_MODEL),
            (LBL_SW_VERSION, KEY_SW_VERSION_DETAIL),
            (LBL_UPTIME, KEY_UPTIME_DETAIL),
            (LBL_PANORAMA, KEY_PANORAMA),
            (LBL_ACTIVE, KEY_ACTIVE),
            (LBL_ALT_SERIAL, KEY_ALT_SERIAL),
            (LBL_ALT_IP, KEY_ALT_IP),
            (LBL_ARE, KEY_ARE),
            # Version information
            (LBL_APP_VERSION, KEY_APP_VERSION_DETAIL),
            (LBL_THREAT_VERSION, KEY_THREAT_VERSION_DETAIL),
            (LBL_AV_VERSION, KEY_AV_VERSION_DETAIL),
            (LBL_WILDFIRE_VERSION, KEY_WILDFIRE_VERSION_DETAIL),
            (LBL_URL_FILTERING_VERSION, KEY_URL_FILTERING_VERSION_DETAIL),
            # Certificate information
            (LBL_DEVICE_CERT_PRESENT, KEY_DEVICE_CERT_PRESENT_DETAIL),
            (LBL_DEVICE_CERT_EXPIRY, KEY_DEVICE_CERT_EXPIRY_DETAIL),
            # Management info
            (LBL_LAST_REFRESH, KEY_LAST_UPDATE),
        ]

        first_ngfw = True
        for ngfw_data in results:
            if not first_ngfw:
                print() # Add a newline between NGFW entries
            first_ngfw = False

            hostname = ngfw_data.get(KEY_HOSTNAME, "Unknown Hostname")
            serial = ngfw_data.get(KEY_SERIAL, "N/A")
            print(f"---- {hostname} ({serial}) ----")

            # Calculate the maximum label length for alignment for this specific NGFW's display
            max_label_len = 0
            for label, _ in attributes_to_print:
                if len(label) > max_label_len:
                    max_label_len = len(label)
            
            for label, key in attributes_to_print:
                value = ngfw_data.get(key, "N/A") # Default to "N/A" if key somehow missing
                if value == '': # Make empty strings more readable
                    value = "-" 
                print(f"{label:<{max_label_len}} : {value}")

        if message:
            print()
            print("\n".join(message))
        print() # Final newline

    def print_panorama_detail_results(self, results=None, message=None):
        """
        Formats and prints detailed Panorama information.
        """
        if not results:
            if message:
                print("\n".join(message))
            else:
                print("No Panoramas found to display details for.")
            print()
            return

        attributes_to_print = [
            (LBL_PAN_SERIAL, KEY_PAN_SERIAL),
            (LBL_PAN_IP_ADDRESS, KEY_PAN_IP_ADDRESS),
            (LBL_PAN_IPV6_ADDRESS, KEY_PAN_IPV6_ADDRESS),
            (LBL_PAN_MAC_ADDRESS, KEY_PAN_MAC_ADDRESS),
            (LBL_PAN_MODEL, KEY_PAN_MODEL),
            (LBL_PAN_SYSTEM_MODE, KEY_PAN_SYSTEM_MODE),
            (LBL_PAN_SW_VERSION, KEY_PAN_SW_VERSION),
            (LBL_PAN_UPTIME, KEY_PAN_UPTIME),
            (LBL_PAN_ACTIVE, KEY_PAN_ACTIVE),
            (LBL_PAN_ALT_IP, KEY_PAN_ALT_IP),
            (LBL_PAN_NGFW_COUNT, KEY_PAN_NGFW_COUNT),
            (LBL_PAN_LIC_DEV_CAP, KEY_PAN_LIC_DEV_CAP),
            # Version information
            (LBL_PAN_APP_VERSION, KEY_PAN_APP_VERSION),
            (LBL_PAN_AV_VERSION, KEY_PAN_AV_VERSION),
            (LBL_PAN_WILDFIRE_VERSION, KEY_PAN_WILDFIRE_VERSION),
            (LBL_PAN_LOGDB_VERSION, KEY_PAN_LOGDB_VERSION),
            # Certificate information
            (LBL_PAN_DEV_CERT_STATUS, KEY_PAN_DEV_CERT_STATUS),
            # Management info
            (LBL_PAN_LAST_SYS_REFRESH, KEY_PAN_LAST_SYS_REFRESH),
        ]

        first_pan = True
        for pan_data in results:
            if not first_pan:
                print() 
            first_pan = False

            hostname = pan_data.get(KEY_PAN_HOSTNAME, "Unknown Panorama")
            serial = pan_data.get(KEY_PAN_SERIAL, "N/A")
            print(f"---- {hostname} ({serial}) ----")

            max_label_len = 0
            for label, _ in attributes_to_print:
                if len(label) > max_label_len:
                    max_label_len = len(label)
            
            for label, key in attributes_to_print:
                value = pan_data.get(key, "N/A") 
                if value == '' or value is None: # Handle None explicitly as well
                    value = "-" 
                print(f"{label:<{max_label_len}} : {value}")

        if message:
            print()
            print("\n".join(message))
        print() # Final newline

    def write_results_to_csv(self, filename: str, headers_dict: dict, results: list):
        """
        Writes standard tabular results to a CSV file.

        Args:
            filename (str): The name of the CSV file to write.
            headers_dict (dict): Dictionary mapping display header names (str) to data keys (str).
                                 Example: {"NGFW": "ngfw", "Virtual Router": "virtual_router"}
            results (list[dict]): List of dictionaries, where each dictionary is a row.

        Returns:
            tuple: (bool, str) indicating success and a message.
        """
        try:
            # Extract display names for the header row from the dictionary keys
            header_display_names = list(headers_dict.keys())
            # Extract data keys from the dictionary values to access data from results
            data_keys = list(headers_dict.values())

            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(header_display_names)  # Write the display header row

                if results:
                    for row_data in results:
                        # Ensure all keys are present, providing 'N/A' if a key is missing
                        writer.writerow([row_data.get(key, 'N/A') for key in data_keys])
                else: # Handle case where results might be an empty list but headers are present
                    pass # Just write the header if no data rows

            return True, f"Successfully wrote data to {filename}"
        except IOError as e:
            logging.error(f"IOError writing to CSV file {filename}: {e}")
            return False, f"Error writing to CSV file {filename}: {e}"
        except Exception as e:
            logging.error(f"Unexpected error during CSV writing for {filename}: {e}")
            return False, f"An unexpected error occurred while writing to {filename}: {e}"

    def write_detail_to_csv_generic(self, filename: str, attributes_list: list, results_list: list):
        """
        Writes detailed results (attribute-value pairs per item) to a CSV file.
        Each item in results_list becomes a row. Columns are derived from attributes_list.

        Args:
            filename (str): The name of the CSV file to write.
            attributes_list (list): A list of (label, key) tuples.
                                    Labels are used as CSV headers.
                                    Keys are used to extract data from results_list items.
            results_list (list[dict]): A list of dictionaries, where each dictionary is an item (e.g., an NGFW or Panorama).

        Returns:
            tuple: (bool, str) indicating success and a message.
        """
        try:
            if not attributes_list:
                return False, f"No attributes defined for detailed CSV export to {filename}."

            # Use labels from attributes_list as CSV headers
            header_labels = [label for label, key in attributes_list]
            # Use keys from attributes_list to extract data
            data_keys = [key for label, key in attributes_list]

            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(header_labels)  # Write the header row

                if results_list:
                    for item_data in results_list:
                        # Construct row by fetching data using keys, default to "N/A" if key missing
                        row_to_write = [item_data.get(key, "N/A") for key in data_keys]
                        writer.writerow(row_to_write)
                else: # Handle case where results might be an empty list but attributes are present
                    pass # Just write the header if no data rows


            return True, f"Successfully wrote detailed data to {filename}"
        except IOError as e:
            logging.error(f"IOError writing detailed data to CSV file {filename}: {e}")
            return False, f"Error writing detailed data to CSV file {filename}: {e}"
        except Exception as e:
            logging.error(f"Unexpected error during detailed CSV writing for {filename}: {e}")
            return False, f"An unexpected error occurred while writing detailed data to {filename}: {e}"

    def write_interfaces_v6_to_csv(self, filename: str, results: list):
        """
        Writes IPv6 interface data to a CSV file.
        Each IPv6 address for an interface gets its own row in the CSV.

        Args:
            filename (str): The name of the CSV file to write.
            results (list[dict]): List of dictionaries, each representing an interface
                                  and containing 'ipv6_address_list'. Expected keys in each dict
                                  are based on constants like KEY_NGFW, KEY_VR, KEY_NAME, etc.

        Returns:
            tuple: (bool, str) indicating success and a message.
        """
        try:
            # Define CSV headers explicitly for this custom format
            csv_headers = [HDR_NGFW, HDR_VR, HDR_NAME, HDR_TAG, HDR_ZONE, HDR_IPV6_ADDRESSES]

            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(csv_headers)

                if results:
                    for r_data in results: # Each r_data is a dictionary for an interface
                        ngfw = r_data.get(KEY_NGFW, 'N/A')
                        vr = r_data.get(KEY_VR, 'N/A')
                        name = r_data.get(KEY_NAME, 'N/A')
                        tag = str(r_data.get(KEY_TAG, 'N/A')) # Ensure tag is a string
                        zone = r_data.get(KEY_ZONE, 'N/A')
                        ipv6_list = r_data.get(KEY_IPV6_ADDRESS_LIST, [])

                        if ipv6_list: # If there are IPv6 addresses for this interface
                            for ipv6_addr in ipv6_list:
                                writer.writerow([ngfw, vr, name, tag, zone, ipv6_addr])
                        else:
                            # If an interface is included in results but has no IPv6 addresses,
                            # write a row indicating this.
                            writer.writerow([ngfw, vr, name, tag, zone, "(No IPv6 Addresses Found)"])
                else: # Handle case where results might be an empty list
                    pass # Just write the header if no data rows

            return True, f"Successfully wrote IPv6 interface data to {filename}"
        except IOError as e:
            logging.error(f"IOError writing IPv6 interface data to CSV file {filename}: {e}")
            return False, f"Error writing IPv6 interface data to CSV file {filename}: {e}"
        except Exception as e:
            logging.error(f"Unexpected error during IPv6 interface CSV writing for {filename}: {e}")
            return False, f"An unexpected error occurred while writing IPv6 interface data to {filename}: {e}"
