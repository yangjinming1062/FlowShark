# -*- coding=utf-8 -*-
import logging
import os
import sys
import traceback

import ujson
from datetime import datetime
from logging.handlers import RotatingFileHandler

"""
提供日志记录功能
"""
LogHelper = None
LogBase = {"status": "ERROR", "exc_info": "", "component": "flow-shark"}


def init_log(size, log_info, host_ip):
    global LogHelper, LogBase
    if not os.path.exists('./Logs/'):
        os.mkdir('./Logs')
    LogHelper = logging.getLogger("错误日志")
    LogHelper.addHandler(RotatingFileHandler('./Logs/error.log', maxBytes=size, backupCount=1))
    LogBase['node_ip'] = host_ip
    if log_info:
        LogHelper.setLevel(logging.INFO)


def log(msg):
    LogBase['exc_at'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    if isinstance(msg, str):
        LogBase['status'] = 'INFO'
        LogBase['exc_info'] = msg
        LogHelper.info(ujson.dumps(LogBase))
    elif isinstance(msg, BaseException):
        if isinstance(msg, KeyboardInterrupt):
            exit(0)
        LogBase['status'] = 'EXCEPTION'
        tb = getattr(msg, "__traceback__", None)
        if tb is not None:
            exc_type = type(msg)
            exc_value = msg
        else:
            exc_type, exc_value, tb = sys.exc_info()
        LogBase['exc_info'] = traceback.format_exception(exc_type, exc_value, tb)
        LogHelper.error(ujson.dumps(LogBase))
    else:
        LogBase['status'] = 'ERROR'
        LogBase['exc_info'] = msg
        LogHelper.error(ujson.dumps(LogBase))
