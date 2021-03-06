#!/usr/bin/env python
# -*- coding: utf-8 -*-
# +--------------------------------------------------------------------------+
# | export_userprofile                                                       |
# +--------------------------------------------------------------------------+
# | Copyright (c) 2004-2017 S.p.A. <info@endian.com>                         |
# |         Endian S.p.A.                                                    |
# |         via Pillhof 47                                                   |
# |         39057 Appiano (BZ)                                               |
# |         Italy                                                            |
# |                                                                          |
# | This program is free software; you can redistribute it and/or modify     |
# | it under the terms of the GNU General Public License as published by     |
# | the Free Software Foundation; either version 2 of the License, or        |
# | (at your option) any later version.                                      |
# |                                                                          |
# | This program is distributed in the hope that it will be useful,          |
# | but WITHOUT ANY WARRANTY; without even the implied warranty of           |
# | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            |
# | GNU General Public License for more details.                             |
# |                                                                          |
# | You should have received a copy of the GNU General Public License along  |
# | with this program; if not, write to the Free Software Foundation, Inc.,  |
# | 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.              |
# +--------------------------------------------------------------------------+
__author__ = "Luca Radaelli"

import yaml
from sys import exit
import os.path
from endian.job.commons import DataSource
from ipaddress import ip_address
from subprocess import check_output
from shlex import split


is_bridged = False
vpn_users_file = '/var/efw/access/user'
vpn_server_conf = '/var/efw/openvpn/server'
vpn_ca_folder = '/var/efw/vpn/ca/cacerts/'
vpn_cert_folder = '/var/efw/vpn/ca/certs/'
ca_cert = vpn_ca_folder+DataSource('openvpn').settings.CA_FILENAME
green_ip = DataSource('ethernet').settings.green_address
conf_to_print = {}
static_param = ['client', 'nobind', 'persist-key', 'persist-tun',
                'verb 2', 'ns-cert-type server', 'comp-lzo' ,
                'resolv-retry infinite']
auth_type_human_readable = {'psk': 'PSK',
                            'cert': 'Certificate',
                            'psk_cert': 'Certificate & PSK'}


def is_private_ip(IP):
    if ip_address(unicode(IP)).is_private:
        DIG='dig +short +time=3 +tries=1 myip.opendns.com @resolver1.opendns.com'
        try:
            process = check_output(split(DIG))
        except subprocess.CalledProcessError as grepexc:
            process = "error code", grepexc.returncode, grepexc.output
    else:
        process = DataSource('uplinks').main.data.IP_ADDRESS
    return process.rstrip()


def get_vpn_users():
    user_list = []
    cont = 0
    try:
        with open(vpn_users_file, "r") as f:
            users = yaml.load_all(f.read())
    except IOError:
        print 'user file not found'
        exit(1)
    for user in users:
        for index, value in user.items():
            """print only enabled users with valid certificate associated"""
            if os.path.isfile(vpn_cert_folder+value['name']+".p12") and value['enabled']:
                cont += 1
                print cont, value['name']
                user_list.append(value['name'])
    if len(user_list) == 0:
        print "No user Certificates found"
        exit(1)
    return user_list


def get_user_cert():
    user_list = get_vpn_users()
    user_id = -1
    while user_id < 0 or user_id > len(user_list):
        try:
            user_id = int(raw_input("Select the ID of the user from the above list: "))
        except ValueError:
            print "Wrong value selected"
    print """\ndownload the certificate from
            \rhttps://{}:10443/manage/ca/certificate/p12?ID={}cert.pem
            \rand send it to the user\n""".format(green_ip, user_list[user_id-1])
    return user_list[user_id-1]


def get_auth_type(inst_id):
    if inst_id['auth_type'] == '':
        cmd_auth = DataSource('openvpn').settings.AUTH_TYPE
    else:
        cmd_auth = inst_id['auth_type']
    if cmd_auth == 'psk':
        conf_to_print['authentication'] = 'auth-user-pass'
        with open(ca_cert, 'r') as fin:
            print "<ca>"
            print fin.read(),
            print "</ca>"
    elif cmd_auth == 'cert':
        user_id = get_user_cert()
        conf_to_print['cert'] = "{}cert.p12".format(user_id)
    elif cmd_auth == 'psk_cert':
        conf_to_print['authentication'] = 'auth-user-pass'
        user_id = get_user_cert()
        conf_to_print['cert'] = "{}cert.p12".format(user_id)


def print_server_instance_conf():
    if DataSource('openvpn').settings.OPENVPN_ENABLED == 'on':
        try:
            with open(vpn_server_conf, "r") as f:
                servers = yaml.load_all(f.read())
        except IOError:
            print 'VPN configration file not found,check if OpenVPN Server is enabled'
            exit(1)
        server = {}
        for srv in servers:
            for srv_id, data in srv.items():
                if data['enabled'] is True:
                    print srv_id
                    if data['remark']:
                        print "Remark: {}".format(data['remark'])
                    print "Instance name: {}".format(data['name'])
                    if data['openvpn_bind_address'] != '':
                        print "Listening on: {}:{}".format(data['openvpn_bind_address'], data['openvpn_port'])
                    else:
                        print "Listening on: *:{}".format(data['openvpn_port'])
                    print "Protocol : {}".format(data['openvpn_protocol'])
                    if data['bridged'] is True:
                        print "Network : bridged - {}".format(data['bridge_to'])
                    else:
                        print "Network : routed - {}".format(data['purple_net'])
                    print "Device type : {}".format(data['device_type'])
                    if data['auth_type']:
                        print "Authentication : {}\n".format(auth_type_human_readable[data['auth_type']])
                    else:
                        print "Authentication : {}\n".format(auth_type_human_readable[DataSource('openvpn').settings.AUTH_TYPE])
                    server[srv_id] = srv[srv_id]
                else:
                    print 'OpenVPN instance disabled,skipping'
        if server:
            return server
        else:
            print 'No OpenVPN instance enabled'
            exit(1)
    else:
        print 'OpenVPN service not enabled'
        exit(1)


def generate_conf(srv):
    instance_id = ''
    while not instance_id:
        try:
            instance_id = int(raw_input("Select the instance ID "))
        except ValueError:
            print "select the correct value"
    print "\nexporting client configuration, copy the output below\n"
    get_auth_type(srv[instance_id])
    conf_to_print['dev'] = srv[instance_id]['device_type']
    conf_to_print['proto'] = srv[instance_id]['openvpn_protocol']
    if srv[instance_id]['openvpn_bind_address']:
        conf_to_print['remote'] = srv[instance_id]['openvpn_bind_address']
    else:
        red_ip = is_private_ip(DataSource('uplinks').main.data.IP_ADDRESS)
        conf_to_print['remote'] = red_ip
    conf_to_print['port'] = srv[instance_id]['openvpn_port']
    if srv[instance_id]['reneg_sec'] and srv[instance_id]['reneg_sec'] != '3600':
        conf_to_print['reneg-sec'] = srv[instance_id]['reneg_sec']
    if srv[instance_id]['digest'] and not srv[instance_id]['disable_encryption']:
        conf_to_print['auth'] = srv[instance_id]['digest']
    elif srv[instance_id]['disable_encryption']:
        conf_to_print['auth'] = 'none'
    if srv[instance_id]['cipher'] and not srv[instance_id]['disable_encryption']:
        conf_to_print['cipher'] = srv[instance_id]['cipher']
    elif  srv[instance_id]['disable_encryption']:
        conf_to_print['cipher'] =  'none'
    for param in static_param:
        print param
    for k, v in conf_to_print.iteritems():
        if k == 'authentication':
            print v
        elif k == 'cert':
            print 'pkcs12', v
        else:
            print k, v


if __name__ == "__main__":
    conf = print_server_instance_conf()
    generate_conf(conf)
