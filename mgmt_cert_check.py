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
        panorama_uptime = dev_name_version['response']['result']['system']['uptime']
        content_version = dev_name_version['response']['result']['system']['app-version']
        supported_versions = ['8.1.21-h3', '8.1.25-h3', '8.1.26', '9.0.16-h7', '9.0.17-h5', '9.1.11-h5', '9.1.12-h7', '9.1.13-h5', '9.1.14-h8', '9.1.16-h5', '9.1.17', '10.0.8-h11', '10.0.11-h4', '10.0.12-h5', '10.1.3-h3', '10.1.4-h6', '10.1.5-h4', '10.1.6-h8', '10.1.7-h1', '10.1.8-h7', '10.1.9-h8', '10.1.10-h5', '10.1.11-h5', '10.1.12', '10.2.0-h2', '10.2.1-h1', '10.2.2-h4', '10.2.3-h11', '10.2.4-h10', '10.2.6-h1', '10.2.7-h3', '10.2.8', '11.0.0-h2', '11.0.1-h3', '11.0.2-h3', '11.0.3-h3',  '11.0.3-h5', '11.0.4', '11.1.0-h2', '11.1.1', '8.1.26-h1', '9.0.17-h5', '9.1.17-h1', '10.0.12-h5,10.1.12', '10.2.8', '11.0.4', '11.1.1', '9.0.6', '9.1.5', '10.0.7', '10.1.2', '10.2.2', '11.0.1', '8.1.26-h1', '9.0.17-h5', '9.1.17-h1', '10.0.12-h5', '10.1.12', '10.2.8', '11.0.4', '11.1.1']

        uri2 = "/api/?type=op&cmd=<show><devices><all></all></devices></show>&key=" + api_key
        full_url = "https://" + ip + uri2
        show_device_all_response = requests.post(full_url, verify=False)
        all_devices = xmltodict.parse(show_device_all_response.text)

    except IOError:
        logging.error("IP Address: "+ip+" connection was refused. Please check connectivity.\n\n")
        skip = True
        pass

    except KeyError:
        skip = True
        pass

    except AttributeError:
        logging.error("No API key was returned.  Insufficient privileges or incorrect credentials given.\n\n")
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
                            # print(f"Certificate expiration date for Model: {model} IP: {ip}, {expiration_date}", "needs to be updated")
                            if model == 'Panorama' or model == 'panorama':
                                model = 'VM Panorama'
                            device_table = Table(title=f"[bold white on red]Model: {model}, Version: {panorama_version}, IP: {ip}, Uptime: {panorama_uptime}, Cert Date: {expiration_date}, needs to be updated.[/]\n\nDevices Managed by this Panorama", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
                            device_table.add_column("Device Name", justify="center")
                            device_table.add_column("IP Address", width=18, justify="center")
                            device_table.add_column("Device Model", justify="center")
                            device_table.add_column("Serial Number", justify="center")
                            device_table.add_column("PANOS Version", justify="center")
                            device_table.add_column("PANOS Supported", justify="center")
                            device_table.add_column("Content Version", justify="center")
                            device_table.add_column("Content Supported", justify="center")
                            device_table.add_column("Uptime", justify="center")
                            device_table.add_column("Custom Certificate", justify="center")
                            device_table.add_column("Status", justify="center")
                            if isinstance(all_devices['response']['result']['devices']['entry'], list):
                                for device in all_devices['response']['result']['devices']['entry']:
                                    try:
                                        if device['sw-version'] in supported_versions:
                                            supported_version = "Yes"
                                        else:
                                            supported_version = "No"
                                    except KeyError:
                                        supported_version = "No"
                                    try:
                                        if device['app-version'] == None:
                                            supported_content_version = "No"
                                        else:
                                            if float(device['app-version'].replace("-", ".")) >= 8795.8489:
                                                supported_content_version = "Yes"
                                            else:
                                                supported_content_version = "No"
                                    except KeyError:
                                        supported_content_version = "No"
                                    if device['connected'] == 'yes':
                                        if supported_version == "Yes" and supported_content_version == "Yes":
                                            device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on green]{supported_version}[/]", device['app-version'], f"[bold white on green]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                            entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                        if supported_version == "No" and supported_content_version == "Yes":
                                            device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on red]{supported_version}[/]", device['app-version'], f"[bold white on green]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                            entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                        if supported_version == "Yes" and supported_content_version == "No":
                                            device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on green]{supported_version}[/]", device['app-version'], f"[bold white on red]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                            entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                        if supported_version == "No" and supported_content_version == "No":
                                            device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on red]{supported_version}[/]", device['app-version'], f"[bold white on red]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                            entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                    else:
                                        device_table.add_row('', '', '', device['serial'], '', '', '', '', '', '', 'disconnected')
                            else:
                                device = all_devices['response']['result']['devices']['entry']
                                try:
                                    if device['sw-version'] in supported_versions:
                                        supported_version = "Yes"
                                    else:
                                        supported_version = "No"
                                except KeyError:
                                    supported_version = "No"
                                try:
                                    if device['app-version'] == None:
                                        supported_content_version = "No"
                                    else:
                                        if float(device['app-version'].replace("-", ".")) >= 8795.8489:
                                            supported_content_version = "Yes"
                                        else:
                                            supported_content_version = "No"
                                except KeyError:
                                    supported_content_version = "No"
                                if device['connected'] == 'yes':
                                    if supported_version == "Yes" and supported_content_version == "Yes":
                                        device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on green]{supported_version}[/]", device['app-version'], f"[bold white on green]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                        entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                    if supported_version == "No" and supported_content_version == "Yes":
                                        device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on red]{supported_version}[/]", device['app-version'], f"[bold white on green]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                        entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                    if supported_version == "Yes" and supported_content_version == "No":
                                        device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on green]{supported_version}[/]", device['app-version'], f"[bold white on red]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                        entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                    if supported_version == "No" and supported_content_version == "No":
                                        device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on red]{supported_version}[/]", device['app-version'], f"[bold white on red]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                        entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                else:
                                    device_table.add_row('', '', '', device['serial'], '', '', '', '', '', '', 'disconnected')
                            console.print(device_table, '\n\n')

                        else:
                            if model == 'Panorama' or model == 'panorama':
                                model = 'VM Panorama'
                            device_table = Table(title=f"[bold white on green]Model: {model}, Version: {panorama_version}, IP: {ip}, Uptime: {panorama_uptime}, Cert Date: {expiration_date}, is patched.[/]\n\nDevices Managed by this Panorama", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
                            device_table.add_column("Device Name", justify="center")
                            device_table.add_column("IP Address", width=18, justify="center")
                            device_table.add_column("Device Model", justify="center")
                            device_table.add_column("Serial Number", justify="center")
                            device_table.add_column("PANOS Version", justify="center")
                            device_table.add_column("PANOS Supported", justify="center")
                            device_table.add_column("Content Version", justify="center")
                            device_table.add_column("Content Supported", justify="center")
                            device_table.add_column("Uptime", justify="center")
                            device_table.add_column("Custom Certificate", justify="center")
                            device_table.add_column("Status", justify="center")
                            if isinstance(all_devices['response']['result']['devices']['entry'], list):
                                for device in all_devices['response']['result']['devices']['entry']:
                                    try:
                                        if device['sw-version'] in supported_versions:
                                            supported_version = "Yes"
                                        else:
                                            supported_version = "No"
                                    except KeyError:
                                        supported_version = "No"
                                    try:
                                        if device['app-version'] == None:
                                            supported_content_version = "No"
                                        else:
                                            if float(device['app-version'].replace("-", ".")) >= 8795.8489:
                                                supported_content_version = "Yes"
                                            else:
                                                supported_content_version = "No"
                                    except KeyError:
                                        supported_content_version = "No"
                                    if device['connected'] == 'yes':
                                        if supported_version == "Yes" and supported_content_version == "Yes":
                                            device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on green]{supported_version}[/]", device['app-version'], f"[bold white on green]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                            entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                        if supported_version == "No" and supported_content_version == "Yes":
                                            device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on red]{supported_version}[/]", device['app-version'], f"[bold white on green]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                            entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                        if supported_version == "Yes" and supported_content_version == "No":
                                            device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on green]{supported_version}[/]", device['app-version'], f"[bold white on red]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                            entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                        if supported_version == "No" and supported_content_version == "No":
                                            device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on red]{supported_version}[/]", device['app-version'], f"[bold white on red]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                            entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                    else:
                                        device_table.add_row('', '', '', device['serial'], '', '', '', '', '', '', 'disconnected')
                            else:
                                device = all_devices['response']['result']['devices']['entry']
                                try:
                                    if device['sw-version'] in supported_versions:
                                        supported_version = "Yes"
                                    else:
                                        supported_version = "No"
                                except KeyError:
                                    supported_version = "No"
                                try:
                                    if device['app-version'] == None:
                                        supported_content_version = "No"
                                    else:
                                        if float(device['app-version'].replace("-", ".")) >= 8795.8489:
                                            supported_content_version = "Yes"
                                        else:
                                            supported_content_version = "No"
                                except KeyError:
                                    supported_content_version = "No"
                                if device['connected'] == 'yes':
                                    if supported_version == "Yes" and supported_content_version == "Yes":
                                        device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on green]{supported_version}[/]", device['app-version'], f"[bold white on green]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                        entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                    if supported_version == "No" and supported_content_version == "Yes":
                                        device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on red]{supported_version}[/]", device['app-version'], f"[bold white on green]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                        entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                    if supported_version == "Yes" and supported_content_version == "No":
                                        device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on green]{supported_version}[/]", device['app-version'], f"[bold white on red]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                        entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                    if supported_version == "No" and supported_content_version == "No":
                                        device_table.add_row(device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'],  f"[bold white on red]{supported_version}[/]", device['app-version'], f"[bold white on red]{supported_content_version}[/]", device['uptime'], device['custom-certificate-usage'], 'connected')
                                        entries.append([ip, device['hostname'], device['ip-address'], device['model'], device['serial'], device['sw-version'], supported_version, device['app-version'], supported_content_version, device['uptime'], device['custom-certificate-usage']])
                                else:
                                    device_table.add_row('', '', '', device['serial'], '', '', '', '', '', '', 'disconnected')
                            console.print(device_table, '\n\n')

            else:
                pass

        except IOError:
            logging.error("IP Address: "+ip+" connection was refused. Please check connectivity.\n\n")
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
    fields = ['Panorama-IP', 'Device-Name', 'IP-Address', 'Model', 'Serial-Number', 'PANOS-Version', 'PANOS-Supported', 'Content-Version', 'CV-Supported', 'Uptime', 'Custom-Certificate']
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
