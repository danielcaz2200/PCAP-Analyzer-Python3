# Title: Network traffic maps visualizer
# Author: Daniel Cazarez
# CPSC 440 Project - Prof. Heckathorn

import pcap_inspector
import os
import sys

pcap_dir = 'pcap_files'


def main(filenames=None, summarize=False, count=False, kml=False):
    if count:
        pcap_inspector.count_pkts(filenames)
    if summarize:
        pcap_inspector.summarize_files(filenames)
    if kml:
        pcap_inspector.pcap_to_kml()


# Run script
if __name__ == '__main__':

    filenames = []
    for filename in os.listdir(pcap_dir):
        # Concatenated path components, entire string
        file_in_dir = os.path.join(pcap_dir, filename)
        filenames.append(file_in_dir)

    if len(sys.argv) > 1:
        if '--count' in sys.argv:
            main(filenames=filenames, count=True)
        if '--summarize' in sys.argv:
            main(filenames=filenames, summarize=True)
        if '--kml' in sys.argv:
            main(kml=True)

    else:
        print('ERROR: You must supply at least one argument.\n')
        print('Usage: "python3 main.py --arg" where arg = --count, --summarize or --kml')
