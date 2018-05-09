import re, ssl, socket, ipaddress, argparse
import xml.etree.ElementTree as ET
import xml.dom.minidom as MD # Only used for 'pretty' xml printing
from subprocess import Popen, PIPE

#
#   cipher_track
#        

parser = argparse.ArgumentParser(description="cipher suite comparison tool")
parser.add_argument('ip_ranges', help="CIDR notation IP ranges.\nTo specify multiple ranges, separate by comma, eg: '192.168.0.1/24,172.16.0.0/16'\nRanges with host bits set may ignore host bits and start from 1... the vagaries of Python")
parser.add_argument('ports', help="list of ports separated by comma, eg: '443,8080,8888'")
args = parser.parse_args()

unaccepted_ciphers = []
accepted_ciphers = [
        'ECDHE-ECDSA-AES256-GCM-SHA384',        
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-SHA384',
        'ECDHE-ECDSA-AES128-SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES256-SHA384',
        'ECDHE-RSA-AES128-SHA256',
        'ECDHE-RSA-AES256-SHA',
        'ECDHE-RSA-AES128-SHA',
        'ECDHE-ECDSA-CHACHA20-POLY1305',
        'ECDHE-RSA-CHACHA20-POLY1305',]

try:
    pArgs = ['openssl', 'ciphers']
    p = Popen(pArgs, stdout=PIPE)
    (output, err) = p.communicate()
    exit_code = p.wait()
except:
    print("Error retrieving OpenSSL ciphers list.")

all_ciphers = str(output).split(':')
for cipher in all_ciphers:
    if cipher not in accepted_ciphers:
        unaccepted_ciphers.append(cipher)

def generate_report_xml(per_host_list):
    top = ET.Element('hosts')
    for host_object in per_host_list:
        host_element = ET.SubElement(top, 'host', {'name':host_object.host})
        if host_object.accepted_ciphers_results:
            accepted_ciphers_element = ET.SubElement(host_element, 'accepted_ciphers')
            for cipher in host_object.accepted_ciphers_results:
                ET.SubElement(accepted_ciphers_element, cipher[1], {'port':str(cipher[0])}).text = str(cipher[2])
        if host_object.unaccepted_ciphers_results:
            unaccepted_ciphers_element = ET.SubElement(host_element, 'unaccepted_ciphers')
            for cipher in host_object.unaccepted_ciphers_results:
                ET.SubElement(unaccepted_ciphers_element, cipher[1], {'port':str(cipher[0])}).text = str(cipher[2])
    tree = ET.ElementTree(top)
    tree.write('cipher_track_results.xml')
    
    tree_string = ET.tostring(top, 'utf-8')
    xml_reparsed = MD.parseString(tree_string)
    xml_reparsed = xml_reparsed.toprettyxml(indent="\t")

    with open('cipher_track_results_pretty.xml', 'wb') as outfile:
        try:
            xml_reparsed = xml_reparsed.encode('utf-8', 'ignore')
        except:
            pass
        outfile.write(xml_reparsed)

def generate_report_csv(per_host_list):
    with open('cipher_track_results.csv', 'w') as outfile:
        outfile.write("ApproveStatus,Host,Port,Cipher,CipherAvailable,Action\n")
        for host_object in per_host_list:
            if host_object.accepted_ciphers_results:
                for cipher in host_object.accepted_ciphers_results:
                    action = "Add"
                    if cipher[2]:
                        action = "No_Change"
                    outfile.write('approved'+','+host_object.host+','+str(cipher[0])+','+cipher[1]+','+str(cipher[2])+','+action+'\n')
            if host_object.unaccepted_ciphers_results:
                for cipher in host_object.unaccepted_ciphers_results:
                    outfile.write('unapproved'+','+host_object.host+','+str(cipher[0])+','+cipher[1]+','+str(cipher[2])+",Remove"'\n')

# Tests a cipher against a server and returns a boolean
def test_cipher(test_cipher, host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock = ssl.wrap_socket(sock, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_SSLv23, ca_certs=None,
            do_handshake_on_connect=True, suppress_ragged_eofs=True, ciphers=test_cipher)
        sock.connect((host, port))
    except ssl.SSLError:
        return False
    except socket.error:
        return False
    return True

class host_object(object):
    host = ""
    accepted_ciphers_results = []
    unaccepted_ciphers_results = []

    def __init__(self, h, a, u):
        self.host = h
        self.accepted_ciphers_results = a
        self.unaccepted_ciphers_results = u

def test_host_alive(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock = ssl.wrap_socket(sock, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_SSLv23, ca_certs=None,
                do_handshake_on_connect=True, suppress_ragged_eofs=True, ciphers=None)
        sock.connect((host, port))
    except ssl.SSLError:
        sock.close()
        return False
    except socket.timeout:
        sock.close()
        return False
    except socket.error:
        return False
    return True

if __name__ == "__main__":
    per_host_list = []
    
    ip_ranges = args.ip_ranges.split(",")
    ports_str = args.ports.split(",")
    ports = []
    for string in ports_str:
        ports.append(int(string))

    # Iterate through all CIDR ranges given
    for ip_range in ip_ranges:
        try:
            ip_range = ip_range.decode('utf-8', 'ignore')
        except:
            pass
        address_list = list(ipaddress.IPv4Network(ip_range, False).hosts())

        # Iterate through all addresses within each CIDR range
        for address in address_list:
            host_alive=False
            print("host: "+str(address))
            
            accepted_ciphers_results = []
            unaccepted_ciphers_results = []

            # On each address, iterate through each port given
            for port in ports:
                host_alive = test_host_alive(str(address), port)
                if host_alive is True:
                    index=0
                    for cipher in accepted_ciphers:
                        accepted_ciphers_results.append((port, cipher, test_cipher(cipher, str(address), port)))
                        print(cipher+": "+str(accepted_ciphers_results[index][2]))
                        index=index+1

                    index=0
                    for cipher in unaccepted_ciphers:
                        if test_cipher(cipher, str(address), port) is True:
                            unaccepted_ciphers_results.append((port, cipher, True))
                            print(cipher+": "+str(unaccepted_ciphers_results[index][2]))
                            index=index+1

            # Once we have the results of all cipher tests, we create a host_object which contains the results,
            #   and add it to the per_host_list. This list will then contain ALL host information, for all IPs given.
            if accepted_ciphers_results or unaccepted_ciphers_results:
                per_host_list.append(host_object(str(address), accepted_ciphers_results, unaccepted_ciphers_results))
    # Send the final per_host_list for processing into reports
    generate_report_xml(per_host_list)
    generate_report_csv(per_host_list)
