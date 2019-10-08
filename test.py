#!/usr/bin/python3

from urllib.parse import urlparse
from multiprocessing import Process, Manager
import argparse
import subprocess



def nmap_scan(hostname, ports, result):
    result['nmap_results'] = subprocess.getoutput("nmap -sV --top-ports " + str(ports) + " " + parsed_uri.hostname)

#TODO make this run on specific ports only 
#nmap -sV host -p21,22,23
def nmap_port_to_scan(hostname, ports):    
    ''.join(ports)

def ssl_scan(hostname, result):
    result['scan_results'] = subprocess.getoutput("sslscan " + hostname)

def nikto_scan(hostname, result):
    result['nikto_results'] = subprocess.getoutput("nikto -h " + hostname)




#Argument parser
parser = argparse.ArgumentParser(description='Run nikto, nmap and SSLscan. Enter in the form of https')

parser.add_argument("host", help="The host that will be scanned")
parser.add_argument('-p', '--ports', help='Specify the number of common ports that you wish to scan.', default=3000, type=int)
parser.add_argument('-P', '--Ports', help='Scan Specific ports', nargs='+')
parser.add_argument('-o', '--output', help='The file name to write to', default="output.txt")
parser.add_argument('-s', '--skip', help='Skip nikto Scan', action='store_true')

args = parser.parse_args()


#URI parser 
parsed_uri = urlparse(args.host)


#default values
sslinfo = "No Certificate on the end point listed"

with Manager() as manager:
    elements = manager.dict()
    
    nmap = Process(target=nmap_scan, args=(parsed_uri.hostname ,args.ports, elements))
    nmap.start()
    
    if parsed_uri.scheme == "https":
        hostname = '{uri.scheme}://{uri.hostname}'.format(uri=parsed_uri)
        sslscan = Process(target=ssl_scan, args=(hostname, elements))
        sslscan.start()
    
    if not args.skip:
        nikto = Process(target=nikto_scan, args=(args.host, elements))
        nikto.start()
    
    
    
    nmap.join()
    print(elements['nmap_results'])
    
    if parsed_uri.scheme == "https":
        sslscan.join()
        print(elements['scan_results'])
        
    if not args.skip:
        nikto.join()
        print(elements['nikto_results'])
