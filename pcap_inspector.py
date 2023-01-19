import dpkt
import socket
import pygeoip
import requests
import pyshark
import os


# Creates a geoIP object for location lookup
# Based off ip address or domain name
gi = pygeoip.GeoIP('GeoLiteCity.dat')
# Fetches public IP address
public_ip = requests.get('https://api.ipify.org').text
mapdata_dir = 'mapdata'
pcap_dir = 'pcap_files'


def count_pkts(filenames) -> None:
    count = 0
    for filename in filenames:
        pcap = pyshark.FileCapture(filename)
        for pkt in pcap:
            count += 1
        print(f'{filename} contains {count} pkts')


def network_conversation(packet) -> str:
    try:
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        return (f'protocol: {protocol} src: {source_address}: (src port) {source_port} --> dest: {destination_address}: (dest port) {destination_port}')
    except AttributeError as e:
        pass


def summarize_files(filenames) -> None:
    for filename in filenames:
        pcap = pyshark.FileCapture(filename)
        print('******************************************************')
        print(f'EXAMINING PACKETS IN: {filename}.pcap')
        print('******************************************************')
        packet_count = 0
        for packet in pcap:
            packet_count += 1
            convo = network_conversation(packet)
            print(convo)

            if packet_count == 10:
                resp = input('Enter q to stop, any key to continue paging: ')
                if resp == 'q' or resp == 'Q':
                    break
                else:
                    packet_count = 0


def format_kml(destination: str) -> str:
    dest = gi.record_by_name(destination)
    src = gi.record_by_name(public_ip)
    try:
        dstlongitude = dest['longitude']
        dstlatitude = dest['latitude']
        srclongitude = src['longitude']
        srclatitude = src['latitude']

        kml = (
            f'<Placemark>\n'
            f'<name>{destination}</name>\n'
            f'<extrude>1</extrude>\n'
            f'<tessellate>1</tessellate>\n'
            f'<styleUrl>#transBluePoly</styleUrl>\n'
            f'<LineString>\n'
            f'<coordinates>{dstlongitude:6f},{dstlatitude:6f}\n{srclongitude:6f},{srclatitude:6f}</coordinates>\n'
            f'</LineString>\n'
            f'</Placemark>\n'
        )

        return kml
    except:
        return ''


def plot_ip_addresses(pcap) -> str:
    kml_points = ''
    # Where ts is timestamp
    # and buf is the raw packet data
    for ts, buf in pcap:
        try:
            # Parse link layer data, network layer data
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data   # Extracts ip datagram

            # src address unused
            source = socket.inet_ntoa(
                ip.src)
            destination = socket.inet_ntoa(ip.dst)

            kml_point = format_kml(destination)
            kml_points = kml_points + kml_point
            # print(kml_points)
        except Exception as ex:
            print(ex)
    return kml_points


def get_kml_format(pcap: dpkt.pcap.Reader) -> str:
    # Create header for kml document
    header = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
        '<Style id="transBluePoly">' \
        '<LineStyle>' \
        '<width>1.5</width>' \
        '<color>FF0066FF</color>' \
        '</LineStyle>' \
        '</Style>'
    footer = '</Document>\n</kml>\n'
    body = plot_ip_addresses(pcap)

    # Format kml doc
    kml_doc = header + body + footer

    return kml_doc


def pcap_to_kml() -> None:
    pcaps = {}

    for filename in os.listdir(pcap_dir):
        # Concatenated path components
        file_in_dir = os.path.join(pcap_dir, filename)
        fp = open(file_in_dir, 'rb')  # Read wireshark file in binary

        pcap = dpkt.pcap.Reader(fp)
        kmldoc = get_kml_format(pcap)
        pcaps[filename] = kmldoc

        fp.close()

    for filename, kmldoc in pcaps.items():
        filename = f'{filename.rstrip(".pcap")}.kml'
        complete_filename = os.path.join(mapdata_dir, filename)

        with open(complete_filename, 'w') as fp:
            fp.write(kmldoc)
