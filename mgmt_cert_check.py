#!/usr/bin/env python3
# *****************************************************************************
# * Copyright (c) 2008-2024, Palo Alto Networks. All rights reserved.         *
# *                                                                           *
# * This Software is the property of Palo Alto Networks. The Software and all *
# * accompanying documentation are copyrighted.                               *
# *****************************************************************************
from getpass import getpass
import json
import sys
import os
import csv
import logging
import xmltodict
from multiprocessing import Process
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing import cpu_count
import requests
import ipaddress
from argparse import RawTextHelpFormatter
from OpenSSL import SSL
import socket
import datetime
import itertools
from rich.console import Console
from rich.table import Table
requests.packages.urllib3.disable_warnings()

console = Console()

e = ''
entries = []
fw_devices_csv = 'fw_devices.csv'
fw_devices_json = 'fw_devices.json'

def get_devices():
    try:
        if len(sys.argv) == 1:
            filename = input("Enter filename that contains the list of Panorama IP Addresses: ")
            username = input("Login: ")
            password = getpass()
            with open(filename) as df:
               devices = df.read().splitlines()

            devices = [x.replace(' ', '') for x in devices]

            while("" in devices):
                devices.remove("")

        else:
            filename = input("Enter filename that contains the list of Panorama IP Addresses: ")
            username = input("Login: ")
            password = getpass()
            malformed_ipaddrs = []
            with open(filename) as df:
               devices = df.read().splitlines()

            devices = [x.replace(' ', '') for x in devices]

            while("" in devices):
                devices.remove("")

        return devices, username, password, filename

    except FileNotFoundError:
        print('File Not Found')
        k=input("press Enter to exit")
        raise SystemExit(1)


def process_list(ip):
    global entries, pan_ip, test
    global supported_devices_count, os_devices_count,content_devices_count, unsupported_devices_count, devices_failed
    skip = False
    sys_info_response = ''
    api_response = ''
    api_key = ''
    result_dict = ''
    port = ''
    try:
        ip = str(ipaddress.ip_address(ip))
        uri = "/api/?type=keygen&user=" + username + "&password=" + requests.utils.quote(password)
        full_url = "https://" + ip + uri
        api_response = requests.post(full_url, verify=False, timeout=15)
        result_dict = xmltodict.parse(api_response.text)
        api_key = result_dict['response']['result']['key']
        #logging.debug("API Key: " + api_key)
        uri1 = "/api/?type=op&cmd=<show><system><info></info></system></show>&key=" + api_key
        full_url = "https://" + ip + uri1
        sys_info_response = requests.post(full_url, verify=False)
        dev_name_version = xmltodict.parse(sys_info_response.text)
        model = dev_name_version['response']['result']['system']['model']
        panorama_device =  dev_name_version['response']['result']['system']['devicename']
        serial = dev_name_version['response']['result']['system']['serial']
        family = dev_name_version['response']['result']['system']['family']
        panorama_version = dev_name_version['response']['result']['system']['sw-version']

        uri2 = "/api/?type=op&cmd=<show><devices><all></all></devices></show>&key=" + api_key
        full_url = "https://" + ip + uri2
        show_device_all_response = requests.post(full_url, verify=False)
        all_devices = xmltodict.parse(show_device_all_response.text)

    except IOError:
        logging.error("IP Address: "+ip+" connection was refused. Please check connectivity.")
        skip = True
        pass

    except KeyError:
        skip = True
        pass

    except AttributeError:
        logging.error("No API key was returned.  Insufficient privileges or incorrect credentials given.")
        skip = True
        pass

    if skip == True:
        pass
        skip = False
    else:
        try:
            expiration_date = ''
            if model == 'Panorama' or model == 'panorama'or model == 'M-100' or model == 'M-500' or model == 'M-200' or model == 'M-600' or model == 'M-300' or model == 'M-700':
                port = 3978
                context = SSL.Context(SSL.SSLv23_METHOD)
                conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                conn.connect((ip, port))
                conn.do_handshake()
                cert = conn.get_peer_cert_chain()
                conn.close()
                date = datetime.datetime.strptime("2024-04-08 14:35:41", "%Y-%m-%d %H:%M:%S")

                for pos, item in enumerate(cert):
                    if str(pos) == '1':
                        expiration_date = datetime.datetime.strptime(item.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ")
                        if expiration_date < date:
                            # print(f"Certificate expiration date for Panorama/PANOS Model: {model} IP: {ip}, {expiration_date}", "needs to be updated")
                            if model == 'Panorama' or model == 'panorama':
                                model = 'VM Panorama'
                            device_table = Table(title=f"Panorama/PANOS Model: {model} IP: {ip}, {expiration_date}, needs to be updated.\n\nDevices Managed by this Panorama", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
                            device_table.add_column("Device Name", justify="center")
                            device_table.add_column("IP Address", width=18, justify="center")
                            device_table.add_column("Device Model", justify="center")
                            device_table.add_column("Serial Number", justify="center")
                            device_table.add_column("PANOS Version", justify="center")
                            device_table.add_column("Content Version", justify="center")
                            if isinstance(all_devices['response']['result']['devices']['entry'], list):
                                for device in all_devices['response']['result']['devices']['entry']:
                                    if device['connected'] == 'yes':
                                        device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], device['app-version'])
                                        entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], device['app-version']])
                                    else:
                                        device_table.add_row('', '', '', device['serial'], '', '')
                                        entries.append([ip, '', '', '', device['serial'], '', ''])
                            else:
                                device = all_devices['response']['result']['devices']['entry']
                                if device['connected'] == 'yes':
                                    device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], device['app-version'])
                                    entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], device['app-version']])
                                else:
                                    device_table.add_row('', '', '', device['serial'], '', '')
                                    entries.append([ip, '', '', '', device['serial'], '', ''])
                            console.print(device_table, '\n\n')

                        else:
                            if model == 'Panorama' or model == 'panorama':
                                model = 'VM Panorama'
                            device_table = Table(title=f"Panorama/PANOS Model: {model} IP: {ip}, {expiration_date}, is patched.\n\nDevices Managed by this Panorama", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
                            device_table.add_column("Device Name", justify="center")
                            device_table.add_column("IP Address", width=18, justify="center")
                            device_table.add_column("Device Model", justify="center")
                            device_table.add_column("Serial Number", justify="center")
                            device_table.add_column("PANOS Version", justify="center")
                            device_table.add_column("Content Version", justify="center")
                            if isinstance(all_devices['response']['result']['devices']['entry'], list):
                                for device in all_devices['response']['result']['devices']['entry']:
                                    if device['connected'] == 'yes':
                                        device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], device['app-version'])
                                        entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], device['app-version']])
                                    else:
                                        device_table.add_row('', '', '', device['serial'], '', '')
                                        entries.append([ip, '', '', '', device['serial'], '', ''])
                            else:
                                device = all_devices['response']['result']['devices']['entry']
                                if device['connected'] == 'yes':
                                    device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], device['app-version'])
                                    entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], device['app-version']])
                                else:
                                    device_table.add_row('', '', '', device['serial'], '', '')
                                    entries.append([ip, '', '', '', device['serial'], '', ''])
                            console.print(device_table, '\n\n')

            else:
                pass

        except IOError:
            logging.error("IP Address: "+ip+" connection was refused. Please check connectivity.")
            skip = True
            pass

        except KeyError as e:
            logging.error(ip, e)
            skip = True
            pass

        except TypeError:
            skip = True
            pass

def sort_create_csv(entries):
    entries.sort()
    entries = list(entries for entries,_ in itertools.groupby(entries))
    fields = ['Panorama-IP', 'Device-Name', 'IP-Address', 'Model', 'Serial-Number', 'PANOS-Version', 'Content-Version']
    with open(fw_devices_csv, 'w') as f:
        write = csv.writer(f)
        write.writerow(fields)
        write.writerows(entries)

def csv_to_json(csvFile, jsonFile):
    # print("Creating JSON Dictionary - "+jsonFile+" from CSV File - "+csvFile+"\n")
    jsonArray = []
    with open(csvFile, encoding='utf-8') as csvf:
        csvReader = csv.DictReader(csvf)

        for row in csvReader:
            jsonArray.append(row)

    with open(jsonFile, 'w', encoding='utf-8') as jsonf:
        jsonString = json.dumps(jsonArray, indent=4)
        jsonf.write(jsonString)

    return (jsonString)

def multi_processing():
    pool = ThreadPool(processes=os.cpu_count())
    res = list(pool.apply_async(process_list, args=(ip,)) for ip in devices)
    pool.close()
    pool.join()
    results = [r.get() for r in res]

devices, username, password, filename = get_devices()
multi_processing()
sort_create_csv(entries)
csv_to_json(fw_devices_csv, fw_devices_json)
