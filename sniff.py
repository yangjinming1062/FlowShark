# -*- coding=utf-8 -*-
import os
import subprocess
from multiprocessing import Process, Queue, Lock

from data import packet_parser
from logger import log


def _get_tshark_parameters(display_filter, packet_count, custom_parameters):
    """Returns the special tshark parameters to be used according to the configuration of this class."""
    params = ["tshark", "-l", "-n", "-T", "json", "-B", "100", "-Y", display_filter, "-M", packet_count]

    if custom_parameters:
        for key, val in custom_parameters.items():
            params += [key, val]
    params += ["--no-duplicate-keys", "-r", "-"]
    return params


def _get_dumpcap_parameters(interface, filters):
    params = ["dumpcap", "-q", "-i", interface, "-w", "-"]
    if filters:
        params += ['-f', ' and '.join(filters)]
    return params


class Sniffer:
    DEFAULT_BATCH_SIZE = 2 ** 11
    PACKET_SEPARATOR = ("%s  },%s" % (os.linesep, os.linesep)).encode()
    END_SEPARATOR = ("}%s]" % os.linesep).encode()
    END_TAG_STRIP_LENGTH = (1 + len(os.linesep))

    def __init__(self, interface, packet_count, display_filter="http", filters=None, custom_parameters=None):
        self.dumpcap_params = _get_dumpcap_parameters(interface, filters)
        self.tshark_params = _get_tshark_parameters(display_filter, packet_count, custom_parameters)
        self.dumpcap_process = None
        self.tshark_process = None
        self.packet_queue = Queue(0)
        self.eof = False

    def sniff(self):
        while not self.eof or not self.packet_queue.empty():
            packet = self.packet_queue.get()
            yield packet

    def start(self):
        read, write = os.pipe()
        self.dumpcap_process = subprocess.Popen(self.dumpcap_params, stdout=write, stderr=subprocess.DEVNULL)
        self.tshark_process = subprocess.Popen(self.tshark_params, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=read)
        queue = Queue(0)
        lock = Lock()
        for i in range(4):
            Process(target=self.parse_packet, args=(queue, lock)).start()
        Process(target=self.get_raw, args=(self.tshark_process.stdout, queue,)).start()

    def get_raw(self, stream, raw_queue, data=b''):
        while not self.eof:
            try:
                new_data = stream.read(self.DEFAULT_BATCH_SIZE)
                data += new_data
                packet, data = self._extract_packet(data)
                if packet:
                    raw_queue.put(packet)
                if not new_data:
                    raise EOFError({'Title': 'Reached EOF', 'data': data})
            except BaseException as ex:
                self.eof = True
                log(ex)

    def parse_packet(self, raw_queue, lock):
        while not self.eof or not raw_queue.empty():
            try:
                raw = raw_queue.get()
                packet = packet_parser(raw)
                if packet:
                    lock.acquire()
                    self.packet_queue.put(packet)
                    lock.release()
            except BaseException as ex:
                log(ex)

    def _extract_packet(self, data):
        tag_start = 0
        if data != b'':
            tag_start = data.find(b"{")
            if tag_start == -1:
                return None, data

        found_separator = None

        tag_end = data.find(self.PACKET_SEPARATOR)
        if tag_end == -1:
            # Not end of packet, maybe it has end of entire file?
            tag_end = data.find(self.END_SEPARATOR)
            if tag_end != -1:
                found_separator = self.END_SEPARATOR
        else:
            # Found a single packet, just add the separator without extras
            found_separator = self.PACKET_SEPARATOR

        if found_separator:
            tag_end += len(found_separator) - self.END_TAG_STRIP_LENGTH
            return data[tag_start:tag_end].strip().strip(b","), data[tag_end + 1:]
        return None, data
