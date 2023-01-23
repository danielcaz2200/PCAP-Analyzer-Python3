# Title: Network traffic maps visualizer
# Author: Daniel Cazarez

import pcap_inspector
import os
import sys
import argparse as ap

pcap_dir = 'pcap_files'
mapdata_dir = 'mapdata'

# Run script
if __name__ == '__main__':
    cwd = os.getcwd()

    # Get absolute paths
    pcap_dir_abs = os.path.join(cwd, pcap_dir)
    mapdata_dir_abs = os.path.join(cwd, mapdata_dir)

    CHECK_FOLDER = os.path.isdir(pcap_dir_abs)
    if not CHECK_FOLDER:
        os.makedirs(pcap_dir_abs)

    CHECK_FOLDER = os.path.isdir(mapdata_dir_abs)
    if not CHECK_FOLDER:
        os.makedirs(mapdata_dir_abs)

    filenames = []
    for filename in os.listdir(pcap_dir_abs):
        # Concatenated path components, entire string
        file_in_dir = os.path.join(pcap_dir_abs, filename)
        filenames.append(file_in_dir)

    parser = ap.ArgumentParser()

    parser.add_argument('--count', action='store_true',
                        help='Counts packets in a Wireshark pcap file')
    parser.add_argument('--summarize', action='store_true',
                        help='Gives line by line summary of packets in a pcap file')
    parser.add_argument('--kml', action='store_true',
                        help='Creates formatted kml file from a pcap file in the pcap_files dir')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        print('ERROR: You must supply at least one argument.\n')
        parser.print_help()
        sys.exit()
    elif not filenames:
        print(
            f"ERROR: You must import at least one wireshark .pcap capture file to: {pcap_dir_abs}"
        )
        sys.exit()
    elif args.count:
        pcap_inspector.count_pkts(filenames=filenames)
    elif args.summarize:
        pcap_inspector.summarize_files(filenames=filenames)
    elif args.kml:
        pcap_inspector.pcap_to_kml()
    else:
        print('ERROR: You must supply a valid argument to the script.\n')
        parser.print_help()
        sys.exit()
