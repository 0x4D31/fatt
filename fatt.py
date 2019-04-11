#!/usr/bin/env python3
# Copyright (c) 2018, Adel "0x4d31" Karimi.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause

# FATT - Fingerprint All The Things
# Supported protocols: SSL/TLS, SSH, RDP, MYSQL
# TODO: support MSSQL, SMB, VNC, MONGO, etc.

import argparse
import pyshark
import os
import json
import logging
import textwrap
from hashlib import md5

__author__ = "Adel '0x4D31' Karimi"
__version__ = "0.2"


CAP_BPF_FILTER = ('tcp port 22 or tcp port 2222 or tcp port 3389 or '
                  'tcp port 443 or tcp port 993 or tcp port 995 or '
                  'tcp port 636 or tcp port 990 or tcp port 992 or '
                  'tcp port 989 or tcp port 563 or tcp port 614 or '
                  'tcp port 3306 or tcp port 80')
DECODE_AS = {'tcp.port==2222': 'ssh', 'tcp.port==3389': 'tpkt',
             'tcp.port==993': 'tls', 'tcp.port==995': 'tls',
             'tcp.port==990': 'tls', 'tcp.port==992': 'tls',
             'tcp.port==989': 'tls', 'tcp.port==563': 'tls',
             'tcp.port==614': 'tls', 'tcp.port==636': 'tls'}
PROTOCOLS = ['TLS', 'SSH', 'RDP', 'HTTP', 'DATA-TEXT-LINES', 'MYSQL']
HASSH_VERSION = '1.0'
RDFP_VERSION = '0.1'

# TODO: remove global vars
protocol_dict = {}
cookie_dict = {}
jlog = fingerprint = pout = ''

def process_packet(packet):
    logger = logging.getLogger()
    global protocol_dict
    record = None
    proto = packet.highest_layer
    if proto not in PROTOCOLS:
        return

    # [ SSH ]
    if proto == 'SSH' and (fingerprint == 'hassh' or fingerprint == 'all'
                           or fingerprint == 'hasshServer'):
        # Extract SSH identification string and correlate with KEXINIT msg
        if 'protocol' in packet.ssh.field_names:
            protocol = packet.ssh.protocol
            srcip = packet.ip.src
            dstip = packet.ip.dst
            sport = packet.tcp.srcport
            dport = packet.tcp.srcport
            key = '{}:{}_{}:{}'.format(srcip, sport, dstip, dport)
            protocol_dict[key] = protocol
        if 'message_code' not in packet.ssh.field_names:
            return
        if packet.ssh.message_code != '20':
            return
        if ("analysis_retransmission" in packet.tcp.field_names or
           "analysis_spurious_retransmission" in packet.tcp.field_names):
            event = event_log(packet, event="retransmission")
            if record and jlog:
                logger.info(json.dumps(event))
            return
        # Client HASSH
        if int(packet.tcp.srcport) > int(packet.tcp.dstport):
            record = client_hassh(packet)
            # Print the result
            if pout:
                print_result(record, 'hassh')
        # Server HASSH
        elif int(packet.tcp.srcport) < int(packet.tcp.dstport):
            record = server_hassh(packet)
            # Print the result
            if pout:
                print_result(record, 'hasshServer')
        if record and jlog:
            logger.info(json.dumps(record))
        return

    # [ tls/TLS ]
    elif (proto == 'TLS') and (fingerprint == 'ja3' or fingerprint == 'ja3s'
                             or fingerprint == 'all'):
        if 'record_content_type' not in packet.tls.field_names:
                return
        # Content Type: Handshake (22)
        if packet.tls.record_content_type != '22':
            return
        # Handshake Type: Client Hello (1) / Server Hello (2)
        if 'handshake_type' not in packet.tls.field_names:
            return
        htype = packet.tls.handshake_type
        if not (htype == '1' or htype == '2'):
            return
        if ("analysis_retransmission" in packet.tcp.field_names or
           "analysis_spurious_retransmission" in packet.tcp.field_names):
            event = event_log(packet, event="retransmission")
        # JA3
        if htype == '1':
            record = client_ja3(packet)
            # Print the result
            if pout:
                print_result(record, 'ja3')
        elif htype == '2':
            record = server_ja3(packet)
            # Print the result
            if pout:
                print_result(record, 'ja3s')
        if record and jlog:
            logger.info(json.dumps(record))
        return

    # [ RDP ]
    elif proto == 'RDP' and (fingerprint == 'rdfp' or fingerprint == 'all'):
        # Extract RDP cookie and correlate with ClientData msg
        if 'rt_cookie' in packet.rdp.field_names:
            cookie_tmp = packet.rdp.rt_cookie
            cookie = cookie_tmp.replace('Cookie: ', '')
            srcip = packet.ip.src
            dstip = packet.ip.dst
            sport = packet.tcp.srcport
            dport = packet.tcp.srcport
            key = '{}:{}_{}:{}'.format(srcip, sport, dstip, dport)
            cookie_dict[key] = cookie
        if 'clientdata' not in packet.rdp.field_names:
            return
        if ("analysis_retransmission" in packet.tcp.field_names or
           "analysis_spurious_retransmission" in packet.tcp.field_names):
            event = event_log(packet, event="retransmission")
            if jlog:
                logger.info(json.dumps(event))
            return
        # Client RDFP
        record = client_rdfp(packet)
        # Print the result
        if pout:
            print_result(record, 'rdfp')
        if record and jlog:
            logger.info(json.dumps(record))

    # [ HTTP ]
    elif (proto == 'HTTP' or proto == 'DATA-TEXT-LINES') and \
         (fingerprint == 'http' or fingerprint == 'all'):
        if 'request' in packet.http.field_names:
            record = client_http(packet)
            # Print the result
            if pout:
                print_result(record, 'client_http')
        elif 'response' in packet.http.field_names:
            record = server_http(packet)
            # Print the result
            if pout:
                print_result(record, 'server_http')
        if record and jlog:
            logger.info(json.dumps(record))
    return


def client_hassh(packet):
    """returns HASSH (i.e. SSH Client Fingerprint)
    HASSH = md5(KEX;EACTS;MACTS;CACTS)
    """
    srcip = packet.ip.src
    dstip = packet.ip.dst
    sport = packet.tcp.srcport
    dport = packet.tcp.srcport
    protocol = None
    key = '{}:{}_{}:{}'.format(srcip, sport, dstip, dport)
    if key in protocol_dict:
        protocol = protocol_dict[key]
    # hassh fields
    ckex = ceacts = cmacts = ccacts = ""
    if 'kex_algorithms' in packet.ssh.field_names:
        ckex = packet.ssh.kex_algorithms
    if 'encryption_algorithms_client_to_server' in packet.ssh.field_names:
        ceacts = packet.ssh.encryption_algorithms_client_to_server
    if 'mac_algorithms_client_to_server' in packet.ssh.field_names:
        cmacts = packet.ssh.mac_algorithms_client_to_server
    if 'compression_algorithms_client_to_server' in packet.ssh.field_names:
        ccacts = packet.ssh.compression_algorithms_client_to_server
    # Log other kexinit fields (only in JSON)
    clcts = clstc = ceastc = cmastc = ccastc = ""
    if 'languages_client_to_server' in packet.ssh.field_names:
        clcts = packet.ssh.languages_client_to_server
    if 'languages_server_to_client' in packet.ssh.field_names:
        clstc = packet.ssh.languages_server_to_client
    if 'encryption_algorithms_server_to_client' in packet.ssh.field_names:
        ceastc = packet.ssh.encryption_algorithms_server_to_client
    if 'mac_algorithms_server_to_client' in packet.ssh.field_names:
        cmastc = packet.ssh.mac_algorithms_server_to_client
    if 'compression_algorithms_server_to_client' in packet.ssh.field_names:
        ccastc = packet.ssh.compression_algorithms_server_to_client
    if 'server_host_key_algorithms' in packet.ssh.field_names:
        cshka = packet.ssh.server_host_key_algorithms
    # Create hassh
    hassh_str = ';'.join([ckex, ceacts, cmacts, ccacts])
    hassh = md5(hassh_str.encode()).hexdigest()
    record = {"timestamp": packet.sniff_time.isoformat(),
              "sourceIp": packet.ip.src,
              "destinationIp": packet.ip.dst,
              "sourcePort": packet.tcp.srcport,
              "destinationPort": packet.tcp.dstport,
              "client": protocol,
              "hassh": hassh,
              "hasshAlgorithms": hassh_str,
              "hasshVersion": HASSH_VERSION,
              "ckex": ckex,
              "ceacts": ceacts,
              "cmacts": cmacts,
              "ccacts": ccacts,
              "clcts": clcts,
              "clstc": clstc,
              "ceastc": ceastc,
              "cmastc": cmastc,
              "ccastc": ccastc,
              "cshka": cshka}
    return record


def server_hassh(packet):
    """returns HASSHServer (i.e. SSH Server Fingerprint)
    HASSHServer = md5(KEX;EASTC;MASTC;CASTC)
    """
    srcip = packet.ip.src
    dstip = packet.ip.dst
    sport = packet.tcp.srcport
    dport = packet.tcp.srcport
    protocol = None
    key = '{}:{}_{}:{}'.format(srcip, sport, dstip, dport)
    if key in protocol_dict:
        protocol = protocol_dict[key]
    # hasshServer fields
    skex = seastc = smastc = scastc = ""
    if 'kex_algorithms' in packet.ssh.field_names:
        skex = packet.ssh.kex_algorithms
    if 'encryption_algorithms_server_to_client' in packet.ssh.field_names:
        seastc = packet.ssh.encryption_algorithms_server_to_client
    if 'mac_algorithms_server_to_client' in packet.ssh.field_names:
        smastc = packet.ssh.mac_algorithms_server_to_client
    if 'compression_algorithms_server_to_client' in packet.ssh.field_names:
        scastc = packet.ssh.compression_algorithms_server_to_client
    # Log other kexinit fields (only in JSON)
    slcts = slstc = seacts = smacts = scacts = ""
    if 'languages_client_to_server' in packet.ssh.field_names:
        slcts = packet.ssh.languages_client_to_server
    if 'languages_server_to_client' in packet.ssh.field_names:
        slstc = packet.ssh.languages_server_to_client
    if 'encryption_algorithms_client_to_server' in packet.ssh.field_names:
        seacts = packet.ssh.encryption_algorithms_client_to_server
    if 'mac_algorithms_client_to_server' in packet.ssh.field_names:
        smacts = packet.ssh.mac_algorithms_client_to_server
    if 'compression_algorithms_client_to_server' in packet.ssh.field_names:
        scacts = packet.ssh.compression_algorithms_client_to_server
    if 'server_host_key_algorithms' in packet.ssh.field_names:
        sshka = packet.ssh.server_host_key_algorithms
    # Create hasshServer
    hasshs_str = ';'.join([skex, seastc, smastc, scastc])
    hasshs = md5(hasshs_str.encode()).hexdigest()
    record = {"timestamp": packet.sniff_time.isoformat(),
              "sourceIp": packet.ip.src,
              "destinationIp": packet.ip.dst,
              "sourcePort": packet.tcp.srcport,
              "destinationPort": packet.tcp.dstport,
              "server": protocol,
              "hasshServer": hasshs,
              "hasshServerAlgorithms": hasshs_str,
              "hasshVersion": HASSH_VERSION,
              "skex": skex,
              "seastc": seastc,
              "smastc": smastc,
              "scastc": scastc,
              "slcts": slcts,
              "slstc": slstc,
              "seacts": seacts,
              "smacts": smacts,
              "scacts": scacts,
              "sshka": sshka}
    return record


def client_ja3(packet):
    # GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
    GREASE_TABLE = ['2570', '6682', '10794', '14906', '19018', '23130',
                    '27242', '31354', '35466', '39578', '43690', '47802',
                    '51914', '56026', '60138', '64250']
    # ja3 fields
    ssl_version = ciphers = extensions = elliptic_curve = ec_pointformat = ''
    if 'handshake_version' in packet.tls.field_names:
        ssl_version = int(packet.tls.handshake_version, 16)
        ssl_version = str(ssl_version)
    if 'handshake_ciphersuite' in packet.tls.field_names:
        cipher_list = [
            c.show for c in packet.tls.handshake_ciphersuite.fields
            if c.show not in GREASE_TABLE]
        ciphers = '-'.join(cipher_list)
    if 'handshake_extension_type' in packet.tls.field_names:
        extension_list = [
            e.show for e in packet.tls.handshake_extension_type.fields
            if e.show not in GREASE_TABLE]
        extensions = '-'.join(extension_list)
    if 'handshake_extensions_supported_group' in packet.tls.field_names:
        ec_list = [str(int(ec.show, 16)) for ec in
                   packet.tls.handshake_extensions_supported_group.fields
                   if str(int(ec.show, 16)) not in GREASE_TABLE]
        elliptic_curve = '-'.join(ec_list)
    if 'handshake_extensions_ec_point_format' in packet.tls.field_names:
        ecpf_list = [ecpf.show for ecpf in
                     packet.tls.handshake_extensions_ec_point_format.fields
                     if ecpf.show not in GREASE_TABLE]
        ec_pointformat = '-'.join(ecpf_list)
    # TODO: add other non-ja3 fields
    server_name = ""
    if 'handshake_extensions_server_name' in packet.tls.field_names:
        server_name = packet.tls.handshake_extensions_server_name
    # Create ja3
    ja3_string = ','.join([
        ssl_version, ciphers, extensions, elliptic_curve, ec_pointformat])
    ja3 = md5(ja3_string.encode()).hexdigest()
    record = {"timestamp": packet.sniff_time.isoformat(),
              "sourceIp": packet.ip.src,
              "destinationIp": packet.ip.dst,
              "sourcePort": packet.tcp.srcport,
              "destinationPort": packet.tcp.dstport,
              "serverName": server_name,
              "ja3": ja3,
              "ja3Algorithms": ja3_string,
              "ja3Version": ssl_version,
              "ja3Ciphers": ciphers,
              "ja3Extensions": extensions,
              "ja3Ec": elliptic_curve,
              "ja3EcFmt": ec_pointformat}
    return record


def server_ja3(packet):
    # GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
    GREASE_TABLE = ['2570', '6682', '10794', '14906', '19018', '23130',
                    '27242', '31354', '35466', '39578', '43690', '47802',
                    '51914', '56026', '60138', '64250']
    # ja3s fields
    ssl_version = ciphers = extensions = ''
    if 'handshake_version' in packet.tls.field_names:
        ssl_version = int(packet.tls.handshake_version, 16)
        ssl_version = str(ssl_version)
    if 'handshake_ciphersuite' in packet.tls.field_names:
        cipher_list = [
            c.show for c in packet.tls.handshake_ciphersuite.fields
            if c.show not in GREASE_TABLE]
        ciphers = '-'.join(cipher_list)
    if 'handshake_extension_type' in packet.tls.field_names:
        extension_list = [
            e.show for e in packet.tls.handshake_extension_type.fields
            if e.show not in GREASE_TABLE]
        extensions = '-'.join(extension_list)
    # TODO: add other non-ja3s fields
    server_name = ""
    if 'handshake_extensions_server_name' in packet.tls.field_names:
        server_name = packet.tls.handshake_extensions_server_name
    # Create ja3s
    ja3s_string = ','.join([
        ssl_version, ciphers, extensions])
    ja3s = md5(ja3s_string.encode()).hexdigest()
    record = {"timestamp": packet.sniff_time.isoformat(),
              "sourceIp": packet.ip.src,
              "destinationIp": packet.ip.dst,
              "sourcePort": packet.tcp.srcport,
              "destinationPort": packet.tcp.dstport,
              "serverName": server_name,
              "ja3s": ja3s,
              "ja3sAlgorithms": ja3s_string,
              "ja3sVersion": ssl_version,
              "ja3sCiphers": ciphers,
              "ja3sExtensions": extensions}
    return record


def client_rdfp(packet):
    """returns ClientData message fields and RDFP
    RDFP = md5(?)
    """
    srcip = packet.ip.src
    dstip = packet.ip.dst
    sport = packet.tcp.srcport
    dport = packet.tcp.srcport
    cookie = None
    key = '{}:{}_{}:{}'.format(srcip, sport, dstip, dport)
    if key in cookie_dict:
        cookie = cookie_dict[key]
    # RDP fields
    verMajor = verMinor = desktopWidth = desktopHeight = colorDepth =\
        sasSequence = keyboardLayout = clientBuild = clientName =\
        keyboardSubtype = keyboardType = keyboardFuncKey = postbeta2ColorDepth\
        = clientProductId = serialNumber = highColorDepth =\
        supportedColorDepths = earlyCapabilityFlags = clientDigProductId =\
        connectionType = pad1Octet = clusterFlags = encryptionMethods =\
        extEncMethods = channelDef_bin = channelCount = optInit = optEncRdp =\
        optEncSc = optEncCs = optPriHigh = optPriMed = optPriLow = optCompRdp\
        = optComp = optShowProto = optRmtCtrlPrs = clusterFlags_tmp = \
        encryptionMethods_tmp = extEncMethods_tmp = ""

    # Client Core Data
    # https://msdn.microsoft.com/en-us/library/cc240510.aspx
    if 'version_major' in packet.rdp.field_names:
        verMajor = packet.rdp.version_major
    if 'version_minor' in packet.rdp.field_names:
        verMinor = packet.rdp.version_minor
    if 'desktop_width' in packet.rdp.field_names:
        desktopWidth = packet.rdp.desktop_width
    if 'desktop_height' in packet.rdp.field_names:
        desktopHeight = packet.rdp.desktop_height
    if 'colordepth' in packet.rdp.field_names:
        colorDepth = packet.rdp.colordepth
    if 'sassequence' in packet.rdp.field_names:
        sasSequence = packet.rdp.sassequence
    if 'keyboardlayout' in packet.rdp.field_names:
        keyboardLayout = packet.rdp.keyboardlayout
    if 'client_build' in packet.rdp.field_names:
        clientBuild = packet.rdp.client_build
    if 'client_name' in packet.rdp.field_names:
        clientName = packet.rdp.client_name
    if 'keyboard_subtype' in packet.rdp.field_names:
        keyboardSubtype = packet.rdp.keyboard_subtype
    if 'keyboard_type' in packet.rdp.field_names:
        keyboardType = packet.rdp.keyboard_type
    if 'keyboard_functionkey' in packet.rdp.field_names:
        keyboardFuncKey = packet.rdp.keyboard_functionkey
    if 'postbeta2colordepth' in packet.rdp.field_names:
        postbeta2ColorDepth = packet.rdp.postbeta2colordepth
    if 'client_productid' in packet.rdp.field_names:
        clientProductId = packet.rdp.client_productid
    if 'serialnumber' in packet.rdp.field_names:
        serialNumber = packet.rdp.serialnumber
    if 'highcolordepth' in packet.rdp.field_names:
        highColorDepth = packet.rdp.highcolordepth
    if 'supportedcolordepths' in packet.rdp.field_names:
        supportedColorDepths = packet.rdp.supportedcolordepths
    if 'earlycapabilityflags' in packet.rdp.field_names:
        earlyCapabilityFlags = packet.rdp.earlycapabilityflags
    if 'client_digproductid' in packet.rdp.field_names:
        clientDigProductId = packet.rdp.client_digproductid
    if 'connectiontype' in packet.rdp.field_names:
        connectionType = packet.rdp.connectiontype
    if 'pad1octet' in packet.rdp.field_names:
        pad1Octet = packet.rdp.pad1octet

    # Client Cluster Data
    # https://msdn.microsoft.com/en-us/library/cc240514.aspx
    if 'clusterflags' in packet.rdp.field_names:
        # BUG: .hex_value and .raw_value return wrong value
        clusterFlags_tmp = packet.rdp.clusterflags
        clusterFlags = int(clusterFlags_tmp, 16)

    # Client Security Data
    # Only for "Standard RDP Security mechanisms"
    # https://msdn.microsoft.com/en-us/library/cc240511.aspx
    if 'encryptionmethods' in packet.rdp.field_names:
        encryptionMethods_tmp = packet.rdp.encryptionmethods.raw_value
        encryptionMethods = int(encryptionMethods_tmp, 16)
    # In French locale clients, encryptionMethods MUST be set to zero and
    # extEncryptionMethods MUST be set to the value to which encryptionMethods
    # would have been set.
    if 'extencryptionmethods' in packet.rdp.field_names:
        extEncMethods_tmp = packet.rdp.extencryptionmethods.raw_value
        extEncMethods = int(extEncMethods_tmp, 16)

    # Client Network Data
    # https://msdn.microsoft.com/en-us/library/cc240512.aspx
    if 'channelcount' in packet.rdp.field_names:
        channelCount = packet.rdp.channelcount
    if 'options_initialized' in packet.rdp.field_names:
        optInit = packet.rdp.options_initialized.base16_value
    if 'options_encrypt_rdp' in packet.rdp.field_names:
        optEncRdp = packet.rdp.options_encrypt_rdp.base16_value
    if 'options_encrypt_sc' in packet.rdp.field_names:
        optEncSc = packet.rdp.options_encrypt_sc.base16_value
    if 'options_encrypt_cs' in packet.rdp.field_names:
        optEncCs = packet.rdp.options_encrypt_cs.base16_value
    if 'options_priority_high' in packet.rdp.field_names:
        optPriHigh = packet.rdp.options_priority_high.base16_value
    if 'options_priority_med' in packet.rdp.field_names:
        optPriMed = packet.rdp.options_priority_med.base16_value
    if 'options_priority_low' in packet.rdp.field_names:
        optPriLow = packet.rdp.options_priority_low.base16_value
    if 'options_compress_rdp' in packet.rdp.field_names:
        optCompRdp = packet.rdp.options_compress_rdp.base16_value
    if 'options_compress' in packet.rdp.field_names:
        optComp = packet.rdp.options_compress.base16_value
    if 'options_showprotocol' in packet.rdp.field_names:
        optShowProto = packet.rdp.options_showprotocol.base16_value
    if 'options_remotecontrolpersistent' in packet.rdp.field_names:
        optRmtCtrlPrs = packet.rdp.options_remotecontrolpersistent.base16_value

    channelDef_bin = ''.join(str(x) for x in [
        optInit, optEncRdp, optEncSc, optEncCs, optPriHigh, optPriMed,
        optPriLow, optCompRdp, optComp, optShowProto, optRmtCtrlPrs])
    # channelDef_dec = int(channelDef_bin, 2)

    # Create RDFP
    rdfp_str = ';'.join(str(x) for x in [
        verMajor, verMinor, clusterFlags, encryptionMethods, extEncMethods,
        channelCount])

    rdfp = md5(rdfp_str.encode()).hexdigest()
    record = {"timestamp": packet.sniff_time.isoformat(),
              "sourceIp": packet.ip.src,
              "destinationIp": packet.ip.dst,
              "sourcePort": packet.tcp.srcport,
              "destinationPort": packet.tcp.dstport,
              "cookie": cookie,
              "rdfp": rdfp,
              "rdfpAlgorithms": rdfp_str,
              "rdfpVersion": RDFP_VERSION,
              "verMajor": verMajor,
              "verMinor": verMinor,
              "desktopWidth": desktopWidth,
              "desktopHeight": desktopHeight,
              "colorDepth": colorDepth,
              "sasSequence": sasSequence,
              "keyboardLayout": keyboardLayout,
              "clientBuild": clientBuild,
              "clientName": clientName,
              "keyboardSubtype": keyboardSubtype,
              "keyboardType": keyboardType,
              "keyboardFuncKey": keyboardFuncKey,
              "postbeta2ColorDepth": postbeta2ColorDepth,
              "clientProductId": clientProductId,
              "serialNumber": serialNumber,
              "highColorDepth": highColorDepth,
              "supportedColorDepths": supportedColorDepths,
              "earlyCapabilityFlags": earlyCapabilityFlags,
              "clientDigProductId": clientDigProductId,
              "connectionType": connectionType,
              "pad1Octet": pad1Octet,
              "clusterFlags": clusterFlags_tmp,
              "encryptionMethods": encryptionMethods_tmp,
              "extEncMethods": extEncMethods_tmp,
              "channelDef": channelDef_bin
              }
    return record


def client_http(packet):
    REQ_WL = ['', '_ws_expert', 'chat', '_ws_expert_message',
              '_ws_expert_severity', '_ws_expert_group', 'request_method',
              'request_uri', 'request_version', 'request_line','request_full_uri',
              'request', 'request_number', 'prev_request_in']
    req_headers = [i for i in packet.http.field_names if i not in REQ_WL]
    client_header_ordering = ','.join(req_headers)
    client_header_hash = md5(client_header_ordering.encode('utf-8')).hexdigest()
    record = {"timestamp": packet.sniff_time.isoformat(),
              "sourceIp": packet.ip.src,
              "destinationIp": packet.ip.dst,
              "sourcePort": packet.tcp.srcport,
              "destinationPort": packet.tcp.dstport,
              "userAgent": packet.http.user_agent,
              "clientHeaderOrder": client_header_ordering,
              "clientHeaderHash": client_header_hash}
    return record


def server_http(packet):
    RESP_WL = ['', '_ws_expert', 'chat', '_ws_expert_message',
               '_ws_expert_severity', '_ws_expert_group', 'response_version',
               'response_code', 'response_code_desc', 'response_phrase',
               'response_line', 'content_length_header', 'response',
               'response_number', 'time', 'request_in', 'response_for_uri',
               'file_data', 'prev_request_in', 'prev_response_in']
    resp_headers = [i for i in packet.http.field_names if i not in RESP_WL]
    server_header_ordering = ','.join(resp_headers)
    server_header_hash = md5(server_header_ordering.encode('utf-8')).hexdigest()
    record = {"timestamp": packet.sniff_time.isoformat(),
              "sourceIp": packet.ip.src,
              "destinationIp": packet.ip.dst,
              "sourcePort": packet.tcp.srcport,
              "destinationPort": packet.tcp.dstport,
              "server": packet.http.server,
              "serverHeaderOrder": server_header_ordering,
              "serverHeaderHash": server_header_hash}
    return record


def event_log(packet, event):
    """log the anomalous packets"""
    if event == "retransmission":
        event_message = "This packet is a (suspected) retransmission"
    # Report the event (only for JSON output)
    msg = {"timestamp": packet.sniff_time.isoformat(),
           "eventType": event,
           "eventMessage": event_message,
           "sourceIp": packet.ip.src,
           "destinationIp": packet.ip.dst,
           "sourcePort": packet.tcp.srcport,
           "destinationPort": packet.tcp.dstport}
    return msg


def print_result(record, fp):
    tmp = ""
    if fp == 'hassh':
        tmp = textwrap.dedent("""\
                    [+] Client SSH_MSG_KEXINIT detected
                        [ {}:{} -> {}:{} ]
                            [-] Identification String: {}
                            [-] hassh: {}
                            [-] hassh Algorithms: {}""").format(
                            record['sourceIp'],
                            record['sourcePort'],
                            record['destinationIp'],
                            record['destinationPort'],
                            record['client'],
                            record['hassh'],
                            record['hasshAlgorithms'])
    elif fp == 'hasshServer':
        tmp = textwrap.dedent("""\
                    [+] Server SSH_MSG_KEXINIT detected
                        [ {}:{} -> {}:{} ]
                            [-] Identification String: {}
                            [-] hasshServer: {}
                            [-] hasshServer Algorithms: {}""").format(
                            record['sourceIp'],
                            record['sourcePort'],
                            record['destinationIp'],
                            record['destinationPort'],
                            record['server'],
                            record['hasshServer'],
                            record['hasshServerAlgorithms'])
    elif fp == 'ja3':
        tmp = textwrap.dedent("""\
                    [+] ClientHello detected
                        [ {}:{} -> {}:{} ]
                            [-] ServerName: {}
                            [-] ja3: {}
                            [-] ja3 Algorithms: {}""").format(
                            record['sourceIp'],
                            record['sourcePort'],
                            record['destinationIp'],
                            record['destinationPort'],
                            record['serverName'],
                            record['ja3'],
                            record['ja3Algorithms'])
    elif fp == 'ja3s':
        tmp = textwrap.dedent("""\
                    [+] ServerHello detected
                        [ {}:{} -> {}:{} ]
                            [-] ja3s: {}
                            [-] ja3s Algorithms: {}""").format(
                            record['sourceIp'],
                            record['sourcePort'],
                            record['destinationIp'],
                            record['destinationPort'],
                            record['ja3s'],
                            record['ja3sAlgorithms'])
    elif fp == 'rdfp':
        tmp = textwrap.dedent("""\
                    [+] RDP ClientData message detected
                        [ {}:{} -> {}:{} ]
                            [-] Cookie: {}
                            [-] RDFP: {}
                            [-] RDFP Algorithms: {}""").format(
                            record['sourceIp'],
                            record['sourcePort'],
                            record['destinationIp'],
                            record['destinationPort'],
                            record['cookie'],
                            record['rdfp'],
                            record['rdfpAlgorithms'])
    elif fp == 'client_http':
        tmp = textwrap.dedent("""\
                    [+] HTTP Request message detected
                        [ {}:{} -> {}:{} ]
                            [-] User-Agent: {}
                            [-] Client Header Ordering: {}
                            [-] Client Header Hash: {}""").format(
                            record['sourceIp'],
                            record['sourcePort'],
                            record['destinationIp'],
                            record['destinationPort'],
                            record['userAgent'],
                            record['clientHeaderOrder'],
                            record['clientHeaderHash'])
    elif fp == 'server_http':
        tmp = textwrap.dedent("""\
                    [+] HTTP Response message detected
                        [ {}:{} -> {}:{} ]
                            [-] User-Agent: {}
                            [-] Server Header Ordering: {}
                            [-] Server Header Hash: {}""").format(
                            record['sourceIp'],
                            record['sourcePort'],
                            record['destinationIp'],
                            record['destinationPort'],
                            record['server'],
                            record['serverHeaderOrder'],
                            record['serverHeaderHash'])
    print(tmp)


def parse_cmd_args():
    """parse command line arguments"""
    desc = """A python script for extracting network fingerprints"""
    parser = argparse.ArgumentParser(description=(desc))
    helptxt = "pcap file to process"
    parser.add_argument('-r', '--read_file', type=str, help=helptxt)
    helptxt = "directory of pcap files to process"
    parser.add_argument('-d', '--read_directory', type=str, help=helptxt)
    helptxt = "listen on interface"
    parser.add_argument('-i', '--interface', type=str, help=helptxt)
    helptxt = "SSH (HASSH), TLS (JA3), and RDP fingerprint. Default: all"
    parser.add_argument(
        '-fp',
        '--fingerprint',
        default='all',
        choices=['ja3', 'ja3s', 'hassh', 'hasshServer', 'rdfp', 'http'],
        help=helptxt)
    helptxt = "a dictionary of {decode_criterion_string: decode_as_protocol} \
        that are used to tell tshark to decode protocols in situations it \
        wouldn't usually."
    parser.add_argument(
        '-da', '--decode_as', type=dict, default=DECODE_AS, help=helptxt)
    helptxt = "BPF capture filter to use (for live capture only).'"
    parser.add_argument(
        '-f', '--bpf_filter', type=str, default=CAP_BPF_FILTER, help=helptxt)
    helptxt = "log the output in json format"
    parser.add_argument(
        '-j', '--json_logging', action="store_true", help=helptxt)
    helptxt = "specify the output log file. Default: fatt.log"
    parser.add_argument(
        '-o', '--output_file', default='fatt.log', type=str, help=helptxt)
    helptxt = "save the live captured packets to this file"
    parser.add_argument(
        '-w', '--write_pcap', default=None, type=str, help=helptxt)
    helptxt = "print the output"
    parser.add_argument(
        '-p', '--print_output', action="store_true", help=helptxt)
    return parser.parse_args()


def setup_logging(logfile):
    """setup logging"""
    logger = logging.getLogger()
    handler = logging.FileHandler(logfile)
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def main():
    """intake arguments from the user and extract RDP client fingerprints."""
    args = parse_cmd_args()
    setup_logging(args.output_file)

    global jlog, fingerprint, pout
    jlog = args.json_logging
    fingerprint = args.fingerprint
    pout = args.print_output

    # Process PCAP file
    if args.read_file:
        cap = pyshark.FileCapture(args.read_file, decode_as=args.decode_as)
        try:
            for packet in cap:
                process_packet(
                    packet,
                    jlog,
                    fingerprint,
                    pout)
            cap.close()
            cap.eventloop.stop()
        except Exception as e:
            print('Error: {}'.format(e))
            pass

    # Process directory of PCAP files
    elif args.read_directory:
        files = [f.path for f in os.scandir(args.read_directory)
                 if not f.name.startswith('.') and not f.is_dir()
                 and (f.name.endswith(".pcap") or f.name.endswith(".pcapng")
                 or f.name.endswith(".cap"))]
        for file in files:
            cap = pyshark.FileCapture(file, decode_as=args.decode_as)
            try:
                for packet in cap:
                    process_packet(
                        packet,
                        jlog,
                        fingerprint,
                        pout)
                cap.close()
                cap.eventloop.stop()
            except Exception as e:
                print('Error: {}'.format(e))
                pass

    # Capture live network traffic
    elif args.interface:
        # TODO: Use a Ring Buffer (LiveRingCapture), when the issue is fixed:
        # https://github.com/KimiNewt/pyshark/issues/299
        cap = pyshark.LiveCapture(
            interface=args.interface,
            decode_as=args.decode_as,
            bpf_filter=args.bpf_filter,
            output_file=args.write_pcap)
        try:
            cap.apply_on_packets(process_packet)
            # for packet in cap.sniff_continuously(packet_count=0):
            # if len(protocol_dict) > 10000:
            # protocol_dict.clear()
            # process_packet(
            #     packet,
            #     jlog=args.json_logging,
            #     fingerprint=args.fingerprint,
            #     pout=args.print_output)
        except (KeyboardInterrupt, SystemExit):
            print("Exiting..\nBYE o/\n")

if __name__ == '__main__':
    main()
