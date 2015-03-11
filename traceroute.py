### Traceroute By AtNes Ness ###

#!/usr/bin/python3

import sys
import socket
import re
import whois


def isIP(adr):
    regExp = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", adr)
    if regExp is not None and regExp.group(0) == adr:
        return True
    return False


def main():

    tracert_port = 33434
    dests = []
    max_hops = 30
    for arg in sys.argv[1:]:
        dests.append(arg)
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    for addr in dests:
        print("Destination: {}".format(addr))

        if isIP(addr):
            dest = addr
        else:
            dest = socket.gethostbyname(addr)
        ttl = 1
        last_reached = True
        while True:
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            recv_socket.bind((b"", tracert_port))
            send_socket.sendto(b"", (dest, tracert_port))
            recv_socket.settimeout(0.2)
            send_socket.settimeout(0.2)
            curr_name = None
            curr_addr = None
            try:
                curr_addr = recv_socket.recvfrom(512)[1][0]
                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr
            except socket.error:
                pass
            finally:
                send_socket.close()
                recv_socket.close()

            if curr_addr is not None:
                try:
                    provider = whois.get_whois_dict(curr_addr, "whois.iana.org")
                    while provider == {}:
                        provider = whois.get_whois_dict(curr_addr, "whois.iana.org")
                    whois_data = whois.get_whois_dict(curr_addr, provider["refer"])
                    while whois_data == {}:
                        whois_data = whois.get_whois_dict(curr_addr, provider["refer"])
                    if "origin" in whois_data:
                        origin = whois_data["origin"]
                    else:
                        origin = "Unknown"
                    if "country" in whois_data:
                        country = whois_data["country"]
                    else:
                        country = "Unknown"
                    whois_info = "asn: {} counrty: {}".format(origin, country)
                except KeyError:
                    whois_info = "LOCAL"

                curr_host = "{} ({}) {}".format(curr_name if dest != curr_addr else addr,
                                                curr_addr, whois_info)
            else:
                curr_host = "* * *"
            if last_reached or curr_addr is not None:
                print("{}\t{}".format(ttl, curr_host))
            if curr_addr is not None:
                last_reached = True
            else:
                last_reached = False
            if curr_addr == dest:
                break
            if ttl >= max_hops:
                print("Destination {} unreachable...".format(dest))
                break
            ttl += 1

if __name__ == "__main__":
    main()