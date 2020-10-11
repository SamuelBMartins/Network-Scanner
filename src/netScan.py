import datetime
import getopt
import ipaddress
import struct
import sys
import socket
import paramiko

from ping3 import ping

"""
todo:
netmask: in autmaticco trovare range ip locali
trovare mac address
"""

ping_report = open(r"report.txt", "w")


def how_to_use():
    print('netScan.py -p <address 1>-<address 2> <ipserver>')
    print('netScan.py -p 192.168.1.1-192.168.1.255 193.246.121.236')


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
    except socket.herror:
        hostname = 'Unknown'

    return hostname


def log(text):
    ping_report.write(text + '\n')
    print(text)


def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((str(ip), port))
    if result == 0:
        log('Port ' + str(port) + ' TCP is open on host ' + str(ip))
    sock.close()


def scan_port_udp(ip, port):
    """
    come nmap il metodo controlla se dopo una richiesta UDP riceviamo un pacchetto
    ICMP di type = 3 e code = 3; questo paccehtto indica che la porta non è raggiungibile
    se non riceviamo questo tipo di pacchetto ICMP e non riceviamo nessuna risposta UDP
    il metodo considera la porta come "probabilmente aperta"
    """

    icmp = socket.getprotobyname('icmp')
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    timeout = struct.pack("ll", 0, 500)
    icmp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
    icmp_socket.bind(("", 33434))

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.settimeout(0.5)
    try:
        udp_socket.sendto(str.encode("payload"), (str(ip), port))
        udp_socket.recvfrom(1024)
        log('Port ' + str(port) + ' UDP is open on host ' + str(ip))
    except socket.timeout:
        pass
    finally:
        udp_socket.close()

    try:
        icmp_response, curr_addr = icmp_socket.recvfrom(512)

        # icmp is not type 3, code 3: port unreachable
        if icmp_response[20] != 3 or icmp_response[21] != 3:
            log('Port ' + str(port) + ' UDP is probably open on host ' + str(ip))

    # timeout exception - no answer
    except BlockingIOError:
        log('Port ' + str(port) + ' UDP is probably open on host ' + str(ip))
    finally:
        icmp_socket.close()


def scan_all_ports(ip):
    ports = [21, 22, 25, 53, 80, 110, 139, 443, 445, 1194, 3306, 8083, 8080]
    for p in ports:
        scan_port(ip, p)
        scan_port_udp(ip, p)


def ping_scan(ip_from, ip_to):
    if int(ip_from) > int(ip_to):
        print('ip_from > ip_to')
        return 'error'

    try:
        for i in range(int(ip_from), int(ip_to) + 1):
            ip = ipaddress.IPv4Address(i)
            try:
                # noinspection PyTypeChecker
                if ping(str(ip), timeout=0.1) is not None:
                    hostname = get_hostname(ip)
                    log(str(ip) + ' [' + hostname + ']')
                    scan_all_ports(ip)

            # avoid error when we try to ping the broadcast address
            except PermissionError:
                pass
    except KeyboardInterrupt:
        sys.exit()
    finally:
        ping_report.close()


def send_report(ip_server):
    """
    mando report su un server sulla porta 443
    vedi file server.py
    :param ip_server:
    :return:
    """
    with open(r"report.txt", "rb") as file_to_send:
        data = file_to_send.read(1024)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = 443
        s.connect((str(ip_server), port))
        s.send(data)
        s.close()
    except KeyboardInterrupt:
        sys.exit(0)


def send_sftp(ip_server):
    """
    manda report sul sftp della supsi
    :param ip_server:
    :return:
    """
    host, port = str(ip_server), 22
    transport = paramiko.Transport((host, port))

    username, password = "name", "pass"
    transport.connect(None, username, password)

    sftp = paramiko.SFTPClient.from_transport(transport)

    if "folder" not in sftp.listdir("root"):
        sftp.mkdir("path/folder")
    filepath = 'path/folder/' + str(datetime.datetime.now()) + '-report.txt'
    localpath = 'report.txt'
    sftp.put(localpath, filepath)

    if sftp:
        sftp.close()
    if transport:
        transport.close()


def main(argv):
    # try permission
    try:
        ping('8.8.8.8', timeout=1)
    except PermissionError:
        print('you need root privileges')

    try:
        opts, args = getopt.getopt(argv, "p:")
    except getopt.GetoptError:
        how_to_use()
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-p':
            ips = str(arg).split("-")
            ip_to = ipaddress.IPv4Address(ips.pop())
            ip_from = ipaddress.IPv4Address(ips.pop())

            ping_scan(ip_from, ip_to)

            #send_report(ipaddress.IPv4Address(argv[2]))
            send_sftp(ipaddress.IPv4Address(argv[2]))
            sys.exit(0)

    how_to_use()
    sys.exit(0)


if __name__ == '__main__':
    main(sys.argv[1:])
