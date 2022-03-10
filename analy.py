from scapy.all import rdpcap

import collections
import datetime
import hashlib
import sqlite3
import json


def analysis(file_name: str, file_hash_sha256: str) -> None:
    dt = datetime.datetime.now()
    dt.strftime('%Y-%m-%d %H:%M:%S')

    pcap_information = {'info': dict()}
    pcap_hash_information = dict()
    pcap_packet_information = dict()

    with open(f'./data/file/{file_hash_sha256}', 'rb') as f:
        data = f.read()
        pcap_hash_information['md5'] = hashlib.md5(data).hexdigest()
        pcap_hash_information['sha256'] = hashlib.sha256(data).hexdigest()
        pcap_hash_information['sha512'] = hashlib.sha512(data).hexdigest()
    pcap_information['info']['hash'] = pcap_hash_information

    # 192.168.0.1 100
    src_ip_list = collections.defaultdict(int)
    dst_ip_list = collections.defaultdict(int)

    # 1234 100
    src_port_list = collections.defaultdict(int)
    dst_port_list = collections.defaultdict(int)

    # 192.168.0.1:1234 100
    src_ip_port_list = collections.defaultdict(int)
    dst_ip_port_list = collections.defaultdict(int)

    pcap_protocol_list = {'TCP': 0, 'UDP': 0}
    packet_data = rdpcap(f'./data/file/{file_hash_sha256}')
    for packet in packet_data:
        try:
            s_ip = packet['IP'].src
            d_ip = packet['IP'].dst

            src_ip_list[str(s_ip)] += 1
            dst_ip_list[str(d_ip)] += 1

            if packet['IP'].proto == 6:
                pcap_protocol_list['TCP'] += 1

                s_port = packet['TCP'].sport
                d_port = packet['TCP'].dport

                src_port_list[str(s_port)] += 1
                dst_port_list[str(d_port)] += 1

                src_ip_port_list[str(s_ip) + ':' + str(s_port)] += 1
                dst_ip_port_list[str(d_ip) + ':' + str(d_port)] += 1

            elif packet['IP'].proto == 17:
                pcap_protocol_list['UDP'] += 1

                s_port = packet['UDP'].sport
                d_port = packet['UDP'].dport

                src_port_list[str(s_port)] += 1
                dst_port_list[str(d_port)] += 1

                src_ip_port_list[str(s_ip) + ':' + str(s_port)] += 1
                dst_ip_port_list[str(d_ip) + ':' + str(d_port)] += 1
        except Exception as e:
            pass

    src_ip_list = dict(sorted(src_ip_list.items(), key=lambda item: item[1], reverse=True))
    dst_ip_list = dict(sorted(dst_ip_list.items(), key=lambda item: item[1], reverse=True))
    src_port_list = dict(sorted(src_port_list.items(), key=lambda item: item[1], reverse=True))
    dst_port_list = dict(sorted(dst_port_list.items(), key=lambda item: item[1], reverse=True))
    src_ip_port_list = dict(sorted(src_ip_port_list.items(), key=lambda item: item[1], reverse=True))
    dst_ip_port_list = dict(sorted(dst_ip_port_list.items(), key=lambda item: item[1], reverse=True))
    pcap_packet_information['protocol'] = pcap_protocol_list
    pcap_packet_information['src_ip'] = src_ip_list
    pcap_packet_information['dst_ip'] = dst_ip_list
    pcap_packet_information['src_port'] = src_port_list
    pcap_packet_information['dst_port'] = dst_port_list
    pcap_packet_information['src_ip_port'] = src_ip_port_list
    pcap_packet_information['dst_ip_port'] = dst_ip_port_list

    pcap_information['info']['packet'] = pcap_packet_information
    with open(f'./data/json/{file_hash_sha256}.json', 'wt') as f:
        json.dump(pcap_information, f, indent=4)

    with sqlite3.connect('DB.db') as conn:
        cur = conn.cursor()
        cur.execute('INSERT INTO file_info (file_name, file_hash, upload_time) VALUES (?,?,?)',
                    (file_name, file_hash_sha256, dt))
        conn.commit()
