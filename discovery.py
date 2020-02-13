#!/usr/bin/env python

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) ifm electronic gmbh
#
# THE PROGRAM IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
#


# This is a sample code to provide an example how the ifm
# IPv4 discovery is implemented. This is code is reduced
# to its bare minimum and does not contain the needed error
# checks one would expect in production environments.
#
# To sniff the traffic between host and device you can use the following tcpdump commandline:
# sudo tcpdump -nnvXSs 0  -i < your interface for example eth0> udp port 3321

# Import of needed python modules
import socket
import threading
from SocketServer import UDPServer, BaseRequestHandler
import struct
import argparse
import sys
import os

# The magic byte for messages from the host to the device
broadcast = bytearray([0x10, 0x20, 0xef, 0xcf, 0x0c, 0xf9, 0x00, 0x00])
# The magic sent from the device as a response to a request
responsemagic = 0x19111981

# The port number for communication. It is recommended to use
# the same port for incoming and outgoing communication this
# help to pierce a hole through a firewall like the default firewall
# under Windows 7. This technique is called
# UDP hole punching (https://en.wikipedia.org/wiki/UDP_hole_punching)
PORT = 3321

def change_ip(s,ip,mac):
    """Helper function to change the IP address"""
    print('Change IP of the device to: {} with mac: {}'.format(ip,":".join("{:02x}".format(ord(c)) for c in device_mac)))
    set_ip = bytearray([0]*20) # create a zero byte buffer
    set_ip[0:4] = [0x10,0x20,0xef,0xce] # inject the magic bytes
    set_ip[4:6] = struct.pack('>H',PORT)
    # set_ip[6:8] > those bytes are reserved and recommended to be filled with 0
    set_ip[8:12] = socket.inet_aton(ip) # convert the IP to 4 byte representation
    # set_ip[12:14] > those bytes are reserved and recommended to be filled with 0
    set_ip[14:] = mac # reuse the MAC address
    s.sendto(set_ip, ("<broadcast>", PORT)) # Send the configuration to the device


if __name__ == "__main__":
    # Check for sudo privileges
    if (os.getuid() != 0):
        print >> sys.stderr, "Check your privileges. Root permissions are required, as shown in the following example:"
        print >> sys.stderr, "sudo python discovery.py -i eth0 -a 192.168.0.69\n"
        sys.exit(1)
    parser = argparse.ArgumentParser(description='ifm IPv4 Discovery')
    parser.add_argument('-i', '--interface',default='eth0',help='provide the network interface to send broadcast to')
    parser.add_argument('-a', '--address',default='',help='Set the IPv4 address of the device')
    args = parser.parse_args()
    if ("{}".format(args.address) != ""):
        print('IP: {}'.format(args.address))
        print('interface: {}'.format(args.interface))
    else:
        print("No IP address specified to be set.")
        print('Just reading on interface: {}'.format(args.interface))

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        # TODO: use a way to detect all interfaces to send the broadcasts
        # here we use a hardcoded interface as an example
        s.setsockopt(socket.SOL_SOCKET, 25, args.interface) # 25 is the magic number to use a specific interface 'SO_BINDTODEVICE'
        s.bind(('', PORT))
        s.settimeout(5)
    except IOError:
        print >> sys.stderr, "Socket setup failed. Does the specified interface exist? Check using: "
        print >> sys.stderr, "ifconfig"
        sys.exit(1)

    print("Trying to find server...")
    s.sendto(broadcast, ("<broadcast>", PORT))
    try:
        response,server = s.recvfrom(8) # we typically receive our own broadcast
        # TODO use an loop with timeout to scan for the right response
        response,server = s.recvfrom(360) # receive the reply from the device
        mac = []
        # check if the response matches the expected magic bytes
        if responsemagic ==  struct.unpack('>I',response[0:4])[0]:
            print('Magic matched sender: {}'.format(server))
            device_ip = socket.inet_ntoa(response[4:8])
            print('device IPv4 addr:   {}'.format(device_ip))
            gateway_ip = socket.inet_ntoa(response[8:12])
            print('gateweay IPv4 addr: {}'.format(gateway_ip))
            subnetmask = socket.inet_ntoa(response[12:16])
            print('IPv4 subnetmask:    {}'.format(subnetmask))
            port = struct.unpack('>H',response[16:18])[0]
            print('XML-RPC port:       {}'.format(port))
            vendor_id = struct.unpack('>H',response[18:20])[0]
            print('Vendor-ID:          0x{:04x}'.format(vendor_id))
            device_id = struct.unpack('>H',response[20:22])[0]
            print('Device-ID:          0x{:04x}'.format(device_id))
            mac=response[32:38]
            device_mac = response[32:38]
            print('Device-MAC:         {}'.format(":".join("{:02x}".format(ord(c)) for c in device_mac)))
            device_flags = struct.unpack('>H',response[38:40])[0]
            print('Device-Flags:       0x{:04x}'.format(device_id))
            device_hostname = response[40:104]
            print('Device-Hostname:    {}'.format(device_hostname))
            device_devicename = response[104:]
            print('Device-Name:        {}'.format(device_devicename))
            if ("{}".format(args.address) != ""):
                change_ip(s,args.address,mac)
            # Due to the fact we are using UDP it is recommended to check if the IP change
            # was successful. The easiest way might be to use the broadcast again

    except socket.timeout as e:
        print("Could not find ipv4 discovery server {}".format(str(e)))
    # closing the socket
    s.close()
