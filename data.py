# -*- coding=utf-8 -*-
import binascii
import re
import ujson
import uuid
from datetime import datetime
from urllib import parse
from logger import log

DEL_BAD_CHARS = {bad_char: None for bad_char in range(0x00, 0x20) if bad_char not in (0x09, 0x0a, 0x0d)}
DEL_BAD_CHARS.update({bad_char: None for bad_char in range(0xd800, 0xe000)})
DEL_BAD_CHARS.update({bad_char: None for bad_char in range(0xfffe, 0x10000)})


def packet_parser(json_pkt):
    pkt_dict = ujson.loads(json_pkt.decode(errors='ignore').translate(DEL_BAD_CHARS))
    frame_dict = pkt_dict['_source']['layers'].pop('frame')
    http_layer = _check_http(pkt_dict)
    if http_layer:
        body = http_layer.get('http.file_data', '')
        packet = {'sniff_time': frame_dict['frame.time_epoch'],
                  'number': frame_dict.get('frame.number', '0'),
                  'body': body,
                  'hex': binascii.hexlify(body.encode("utf-8", "backslashreplace")).decode("utf-8", "backslashreplace"),
                  'response_flag': 'http.response' in http_layer}

        if packet['response_flag']:
            request_in = http_layer.get('http.request_in') or http_layer.get('http.prev_request_in')
            if request_in is None:
                log(str({'Title': 'Resp Missing Request_in', 'layer': http_layer}))
                return None
            packet['url'] = http_layer.get('http.response_for.uri', None)
            packet['request_in'] = request_in
        else:
            ip_prefix = 'ip'
            ip_layer = pkt_dict['_source']['layers'].pop('ip', None)
            tcp_layer = pkt_dict['_source']['layers'].pop('tcp', None)
            if ip_layer is None:
                return None # 过滤掉ipv6的地址
                ip_layer = pkt_dict['_source']['layers'].pop('ipv6', None)
                ip_prefix = 'ipv6'
            if ip_layer is None or tcp_layer is None:
                log({'Title': 'Without TCP/IP', 'item': pkt_dict['_source']['layers']})
                return None
            packet['src_ip'] = ip_layer[f'{ip_prefix}.src_host']
            packet["src_port"] = tcp_layer['tcp.srcport']
            packet["dst_ip"] = ip_layer[f'{ip_prefix}.dst_host']
            packet["dst_port"] = tcp_layer['tcp.dstport']
            packet['url'] = http_layer.get('http.request.full_uri', None)

        packet['http_layer'] = http_layer
        return packet


def http_combiner(req, resp, suffix_set):
    """
    数据拼装，将捕获到的一次完整对话转换成指定格式的数据
    :return:待保存的数据结构
    :rtype: dict
    """
    resp_lines = _get_lines(resp['http_layer'])
    tmp = _get_resp_first(resp['http_layer'])
    if tmp is None:
        log(str({'Title': 'Resp Missing First Line', 'layer': resp['http_layer']}))
        return None
    resp_first_line, code = tmp
    resp_header = _get_header(resp_lines)

    if 'Content-Type' in resp_header:
        if resp_header['Content-Type'].lower().find('image') > -1:
            return None

    req_lines = _get_lines(req['http_layer'])
    tmp = _get_req_first(req['http_layer'])
    if tmp is None:
        log(str({'Title': 'Req Missing First', 'layer': req['http_layer']}))
        return None
    req_first_line, method, uri = tmp
    req_header = _get_header(req_lines)

    url = resp.get('url') or req.get('url') or uri
    for suffix in suffix_set:
        if url.endswith(suffix):
            return None
    return {
            "id": str(uuid.uuid4()),
            "src_ip": req['src_ip'], "src_port": int(req['src_port']),
            "dst_ip": req['dst_ip'], "dst_port": int(req['dst_port']),
            "url": url, "extension": '',
            "req_start": _get_time(req['sniff_time']),
            "resp_end": _get_time(resp['sniff_time']),
            "scheme": 'https' if url.startswith('https') else 'http',
            "req_method": method, "req_path": uri,
            "req_query": ujson.dumps(parse.parse_qs(parse.urlparse(url).query)),
            "req_headers": ujson.dumps(req_header),
            "req_cookies": req_header.get("Cookie", ''),
            "req_raw_ascii": req_first_line + ''.join(req_lines) + r'\r\n' + req['body'],
            "req_body": req['body'],
            "req_body_hex": req['hex'],
            "resp_headers": ujson.dumps(resp_header),
            "resp_cookies": resp_header.get("Cookie", ''),
            "resp_raw_ascii": resp_first_line + ''.join(resp_lines) + r'\r\n' + resp['body'],
            "resp_body": resp['body'],
            "resp_body_hex": resp['hex'],
            "resp_status_code": code,
            "server": resp_header.get('Server', ''),
            "referer": req_header.get('Referer', '')}


def _check_http(pkt_dict):
    def is_http(layer):
        for k in layer.keys():
            if k.startswith('http.'):
                return True
        return False

    http_layer = pkt_dict['_source']['layers'].pop('http', None)
    if http_layer is None:
        log(str({'Title': 'Without Http', 'item': pkt_dict['_source']['layers']}))
        return None
    elif isinstance(http_layer, list):
        log(str({'Title': 'Exceptional HTTP', 'layers': http_layer}))
        for layer in http_layer:
            if is_http(layer):
                http_layer = layer
                break
        else:
            log(str({'Title': 'List HTTP', 'layers': http_layer}))
            return None
    elif isinstance(http_layer, dict):
        if not is_http(http_layer):
            log(str({'Title': 'Exceptional HTTP', 'layer': http_layer}))
            return None
    else:
        log(str({'Title': 'Exceptional HTTP', 'http': http_layer}))
        return None
    return http_layer


def _get_lines(layer):
    for k, v in layer.items():
        if isinstance(v, list) and re.match('http.*.line', k):
            return v
    return []


def _get_header(lines):
    """
    获取报文头
    :return: 字典格式Headers
    :rtype: dict
    """
    header = {}
    for line in lines:
        line = str(line).strip()
        index = line.find(':')
        header[line[:index]] = line[index + 2:]
    return header


def _get_time(sniff_timestamp):
    try:
        timestamp = float(sniff_timestamp)
    except ValueError:
        # If the value after the decimal point is negative, discard it
        # Google: wireshark fractional second
        timestamp = float(sniff_timestamp.split(".")[0])
    timestamp -= 28800  # UTC减八小时
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def _get_req_first(layer):
    for k, v in layer.items():
        try:
            if isinstance(v, dict):
                method = v['http.request.method']
                uri = v['http.request.uri']
                version = v.get('http.request.version', 'HTTP/1.1')
                return f'{method} {uri} {version}\r\n', method, uri
        except:
            continue


def _get_resp_first(layer):
    for k, v in layer.items():
        try:
            if isinstance(v, dict):
                resp_re = re.match(r'^(.*?) (\d*) (.*)', k)
                if resp_re:
                    return k, int(resp_re.group(2))
                else:
                    version = v.get('http.response.version', 'HTTP/1.1')
                    code = v['http.response.code']
                    phrase = v.get('http.response.phrase')
                    return f'{version} {code} {phrase}\r\n', int(code)
        except:
            continue
