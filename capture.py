# -*- coding=utf-8 -*-
"""
Usage:
    capture.py <Interface>  [--timeout=<seconds>] [--count=N] [-i | --info]
                            [--log_size=<size>] [--log_path=<path>]
                            [--heartbeat=<seconds>]
                            [--filter=<expression>]...
                            [--excluded=<suffix>]
                            [--https=<RSA_info>]...

Arguments:
    <Interface>    需要监听的网卡名称
Options:
    --count=N                       Tshark会话重置参数：当达到该数量时重置会话，影响tshark使用的内存量 [default: 100000]
    --excluded=<suffix>             想要排除的流量类型，默认已支持.css .js .zip .tar .tgz .gz .rar .exe .mov .mpg .mpeg
                                    .avi .asf .mp3 .mp4 .rm .wav .wma .wmv .gif .jpg .jpeg .png .tif .bmp，
                                    填写时不需要写“.”例如：--excluded="js zip" 或 --excluded=js
    --filter=<expression>           Dumpcap过滤条件：例如：--host="src net 127.0.0.1" --host="not host 10.213.121.13"
    --https=<RSA_info>              解析HTTPs流量所需参数：--https="ssl.keys_list:IP地址,端口号,http,密钥位置,密钥密码"
    --heartbeat=<seconds>           心跳日志记录频率 [default: 60]
    --log_path=<path>               输出的流量日志的路径 [default: /opt/logs/netflow-https-flow_tshark.log]
    --log_size=<size>               日志文件大小，当到达该值时自动切割，默认50M：50*1024*1024 [default: 52428800]
    --timeout=<seconds>             请求包保留时长，超时未得到响应包时进行丢弃 [default: 3600]
    -i, --info                      是否记录普通信息，默认不记录
"""
import logging
import os
import sys
import psutil
from time import sleep, time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from multiprocessing import Process, Queue
from threading import Thread

from data import http_combiner
from logger import log, init_log
from sniff import Sniffer

import ujson
from docopt import docopt


def heart_beat(pid, wait_time, path='./Logs/heartbeat.log'):
    print(f'current pid:{pid}')

    base = {"component": "flow-shark", "node_ip": HostIP}
    parent_process = psutil.Process(pid)
    heart_writer = logging.getLogger('heart_writer')
    heart_writer.addHandler(RotatingFileHandler(path, maxBytes=LogRotateSize, backupCount=1))
    heart_writer.setLevel(logging.INFO)
    next_time = time()
    while True:
        try:
            next_time += wait_time
            children = parent_process.children(True)
            state = {pid: {'status': parent_process.status(), 'memory': parent_process.memory_percent(), 'CPU': parent_process.cpu_percent(0.1)}}
            state.update({p.pid: {'name': p.name(), 'status': p.status(), 'memory': p.memory_percent(), 'CPU': p.cpu_percent(0.1)} for p in children})
            base.update({'heartbeated_at': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'), 'state': state})
            heart_writer.info(ujson.dumps(base))
            sleep(next_time - time())
        except BaseException as ex:
            log(ex)
            sleep(1)


def log_writer(log_path):
    logger = logging.getLogger('http_flow')
    logger.addHandler(RotatingFileHandler(log_path, maxBytes=LogRotateSize, backupCount=2))
    logger.setLevel(logging.INFO)
    while True:
        try:
            req, resp = FlowQueue.get()
            message = http_combiner(req, resp, UrlSuffixSet)
            if message:
                logger.info(ujson.dumps(message))
        except BaseException as ex:
            log(ex)


def clean_cache():
    next_time = time()
    while True:
        try:
            next_time += 180
            except_keys = []
            now = time()
            for k, v in HttpCatch.items():
                if now - v[1] < Timeout:  # 丢弃{TIMEOUT}秒都没获得响应的请求包信息
                    break
                else:
                    except_keys.append(k)
            for k in except_keys:
                HttpCatch.pop(k)
            sleep(next_time - time())
        except BaseException as ex:
            log(ex)


def listen(interface):
    sniffer = Sniffer(interface, PacketCount, "http", filters=CustomFilters, custom_parameters=HttpsKey)
    sniffer.start()
    try:
        for item in sniffer.sniff():
            if item['response_flag']:
                if item['request_in'] in HttpCatch:
                    FlowQueue.put((HttpCatch.pop(item['request_in'])[0], item))
                else:
                    HttpCatch[item['request_in']] = (item, time())
            else:
                if item['number'] in HttpCatch:
                    FlowQueue.put((item, HttpCatch.pop(item['number'])[0]))
                else:
                    HttpCatch[item['number']] = (item, time())
    except BaseException as ex:
        log(ex)


if __name__ == '__main__':

    def get_host_ip():
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip

    HostIP = get_host_ip()
    FlowQueue = Queue(0)
    UrlSuffixSet = {'.css', '.js', '.zip', '.tar', '.tgz', '.gz', '.rar', '.exe',
                    '.mov', '.mpg', '.mpeg', '.avi', '.rm', '.asf', '.mp3', '.mp4',
                    '.wav', '.wma', '.wmv', '.gif', '.jpg', '.jpeg', '.png', '.tif', '.bmp'}
    HttpCatch = {}

    options = docopt(__doc__, argv=sys.argv[1:], version='FlowShark v1.1')
    Timeout = int(options['--timeout'])
    PacketCount = options['--count']
    LogRotateSize = int(options['--log_size'])
    HttpsKey = {'-o': o for o in options['--https']} if options['--https'] else {}
    CustomFilters = options['--filter'] if options['--filter'] else []
    if options['--excluded']:
        for suffix in options['--excluded'].split(' '):
            UrlSuffixSet.append(f'.{suffix}')

    init_log(LogRotateSize, options['--info'], HostIP)

    try:
        Thread(target=clean_cache, name='CleanCache').start()
        Process(target=log_writer, args=(options['--log_path'],), name='FlowSharkLogger').start()
        Thread(target=heart_beat, args=(os.getpid(), int(options['--heartbeat'])), name='HeartBeat').start()
        while True:
            listener = Process(target=listen, args=(options['<Interface>'],), name='Sniffer')
            listener.run()
    except BaseException as e:
        log(e)
