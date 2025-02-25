import io
import ipaddress
import json
from multiprocessing import Process
import subprocess
import numpy as np
from scipy.stats import poisson
import time
import requests
import xml.etree.ElementTree as ET
import logging


def scan_request_per_client():
    REQUESTS_PER_IP = "LogParser -i:IISW3C -recurse:-1 \"SELECT c-ip, count(*) as Hits FROM *.log GROUP BY c-ip ORDER BY Hits DESC\" -o:CSV -stats:OFF"
    BLACK_LIST = "appCmd.exe list config -section:system.webServer/security/ipSecurity | findstr \"allowed=\"\"false\"\"\""
    NUMBER_OF_IP_CHECK = 10
    IP_ADDRESS = 0
    REQUEST_NUMBER = 1
    NUMBER_OF_REQUEST_THREESHOLD = 3000
    key = ""
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': key
    }
    logging.basicConfig(
        filename="dynamicIPBlocker.txt",
        encoding="utf-8",
        filemode="a",
        format="{asctime} - {levelname} - {message}",
        style="{",
        datefmt="%Y-%m-%d %H:%M",
        level=logging.INFO,
    )
    WHITE_LIST_JSON = json.load(open("./whitelist.json"))
    WHITE_LIST = [ipaddress.ip_network(
        f"{item['ip']}/{item['subnet_mask']}", strict=False) for item in WHITE_LIST_JSON]
    requestsPerIPOutput = subprocess.check_output(
        REQUESTS_PER_IP, shell=True).decode("utf-8")
    requestsPerIPData = np.loadtxt(io.StringIO(
        requestsPerIPOutput), dtype=object, delimiter=",", skiprows=1)
    try:
        currentBlackListOutput = subprocess.check_output(
            BLACK_LIST, shell=True).decode("utf-8")
    # findstr returns 1 when completing successfully without any match
    except subprocess.CalledProcessError:
        currentBlackListOutput = ""
    currentBlackListData = set(item.attrib['ipAddress'] for item in ET.fromstring(
        "<root>\n" + currentBlackListOutput + "</root>").findall('.//add'))
    topRequestsPerIPData = []
    for client in requestsPerIPData[:NUMBER_OF_IP_CHECK + len(currentBlackListData)]:
        if client[IP_ADDRESS] not in currentBlackListData and len(topRequestsPerIPData) <= NUMBER_OF_IP_CHECK:
            topRequestsPerIPData.append(client)
    p_lambda = np.mean([int(numeric_string[REQUEST_NUMBER])
                       for numeric_string in topRequestsPerIPData])

    for client in topRequestsPerIPData[:5]:
        inWhiteList = False
        for whileListClient in WHITE_LIST:
            if ipaddress.ip_address(client[IP_ADDRESS]) in whileListClient:
                inWhiteList = True
                break

        if inWhiteList:
            continue

        if poisson.sf(int(client[REQUEST_NUMBER]), p_lambda) <= 0.05:
            if int(client[REQUEST_NUMBER]) > NUMBER_OF_REQUEST_THREESHOLD:
                subprocess.call(
                    f"appcmd.exe set config -section:system.webServer/security/ipSecurity /+\"[ipAddress='{client[IP_ADDRESS]}', allowed='False']\" /commit:apphost", shell=True)
                logging.info(
                    f"IPAddress: {client[IP_ADDRESS]} disallowed because they requested {client[REQUEST_NUMBER]} times per 10 mins.")
                continue
            query = {
                'ipAddress': client[IP_ADDRESS],
                'maxAgeInDays': '90'
            }
            response = requests.request(
                method='GET', url=url, headers=headers, params=query)
            decodedResponse = json.loads(response.text)
            decodedResponseData = decodedResponse['data']
            if decodedResponseData['abuseConfidenceScore'] > 10 and "google.com" not in decodedResponseData['domain']:
                subprocess.call(
                    f"appcmd.exe set config -section:system.webServer/security/ipSecurity /+\"[ipAddress='{client[IP_ADDRESS]}', allowed='False']\" /commit:apphost", shell=True)
                logging.info(
                    f"IPAddress: {client[IP_ADDRESS]} disallowed. Domain name: {decodedResponseData['domain']}.")


if __name__ == '__main__':
    TEN_MINUTES = 600
    while True:
        newPid = Process(target=scan_request_per_client)
        newPid.start()
        newPid.join()
        time.sleep(TEN_MINUTES)
