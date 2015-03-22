    ### Traceroute By AtNes Ness ###

#!/usr/bin/python3

import socket
import re
import whois
import struct
import argparse
import time


def isIP(adr):
    regExp = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", adr)
    if regExp is not None and regExp.group(0) == adr:
        return True
    return False


def main(args):
    tracert_port = 33434
    dests = []
    max_hops = 30
    for arg in args.destinations:
        dests.append(arg)

    for addr in dests:
        print("Destination: {}".format(addr))

        if isIP(addr):
            dest = addr
        else:
            try:
                dest = socket.gethostbyname(addr)
            except Exception:
                print("Unknown destination: {}".format(addr))
                break
        ttl = 1
        while True:
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            header = struct.pack("bbHHhd", 8, 0, 21659, 47382, 256, 2.0503048680879128e-308)
            data = b""
            for i in range(48):
                data += struct.pack("b", i+8)
            send_socket.sendto(header+data, (dest, tracert_port+ttl))
            send_socket.settimeout(1)
            curr_name = None
            curr_addr = None
            try:

                recv = send_socket.recvfrom(1024)
                curr_addr = recv[1][0]

                if not args.dontresolve:
                    try:
                        curr_name = socket.gethostbyaddr(curr_addr)[0]
                    except socket.error:
                        curr_name = curr_addr
            except socket.error as e:
                pass


            finally:
                send_socket.close()

            if curr_addr is not None:

                if not args.dontresolve:
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
                        whois_info = "asn: {} country: {}".format(origin, country)
                    except KeyError:
                        whois_info = "LOCAL"

                    curr_host = "{} ({}) {}".format(curr_name if dest != curr_addr else addr,
                                                curr_addr, whois_info)
                else:
                    curr_host = "{}".format(curr_addr)
            else:
                curr_host = "* * *"

            print("{}\t{}".format(ttl, curr_host))

            if curr_addr == dest:
                break
            if ttl >= max_hops:
                print("Destination {} unreachable...".format(dest))
                break
            ttl += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trace the route to the destination.")
    parser.add_argument("destinations", metavar='IPs', nargs='+', help="destination IPs")
    parser.add_argument("-d", "--dontresolve",action="store_true",  help="Specifies to not resolve addresses"
                                                    " to host names and define country with ASN.")
    args = parser.parse_args()
    main(args)