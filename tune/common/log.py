"""Tune logging handler.

This module adds to logging functionality by adding the option to specify
a context object when calling the various log methods.  If the context object
is not specified, default formatting is used. Additionally, an instance uuid
may be passed as part of the log message, which is intended to make it easier
for admins to find messages related to a specific instance.

It also allows setting of formatting information through conf.

"""

import inspect
import itertools
import logging
import logging.config
import logging.handlers
import os
import socket
import sys
import traceback
import threading
import weakref

import six
from six import moves

_PY26 = sys.version_info[0:2] == (2, 6)


_DEFAULT_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class WeakLocal(threading.local):
    def __getattribute__(self, attr):
        rval = super(WeakLocal, self).__getattribute__(attr)
        if rval:
            # NOTE(mikal): this bit is confusing. What is stored is a weak
            # reference, not the value itself. We therefore need to lookup
            # the weak reference and return the inner value here.
            rval = rval()
        return rval

    def __setattr__(self, attr, value):
        value = weakref.ref(value)
        return super(WeakLocal, self).__setattr__(attr, value)


# NOTE(mikal): the name "store" should be deprecated in the future
store = WeakLocal()


class BaseLoggerAdapter(logging.LoggerAdapter):

    def audit(self, msg, *args, **kwargs):
        self.log(logging.AUDIT, msg, *args, **kwargs)

    def isEnabledFor(self, level):
        if _PY26:
            # This method was added in python 2.7 (and it does the exact
            # same logic, so we need to do the exact same logic so that
            # python 2.6 has this capability as well).
            return self.logger.isEnabledFor(level)
        else:
            return super(BaseLoggerAdapter, self).isEnabledFor(level)


class LazyAdapter(BaseLoggerAdapter):
    def __init__(self, name='unknown', version='unknown'):
        self._logger = None
        self.extra = {}
        self.name = name
        self.version = version

    @property
    def logger(self):
        if not self._logger:
            self._logger = getLogger(self.name, self.version)
            if six.PY3:
                # In Python 3, the code fails because the 'manager' attribute
                # cannot be found when using a LoggerAdapter as the
                # underlying logger. Work around this issue.
                self._logger.manager = self._logger.logger.manager
        return self._logger


class ContextAdapter(BaseLoggerAdapter):
    warn = logging.LoggerAdapter.warning

    def __init__(self, logger, project_name, version_string):
        self.logger = logger
        self.project = project_name
        self.version = version_string
        self._deprecated_messages_sent = dict()

    @property
    def handlers(self):
        return self.logger.handlers

    def deprecated(self, msg, *args, **kwargs):
        """Call this method when a deprecated feature is used.

        If the system is configured for fatal deprecations then the message
        is logged at the 'critical' level and :class:`DeprecatedConfig` will
        be raised.

        Otherwise, the message will be logged (once) at the 'warn' level.

        :raises: :class:`DeprecatedConfig` if the system is configured for
                 fatal deprecations.

        """
        stdmsg = _("Deprecated: %s") % msg
        if CONF.fatal_deprecations:
            self.critical(stdmsg, *args, **kwargs)
            raise DeprecatedConfig(msg=stdmsg)

        # Using a list because a tuple with dict can't be stored in a set.
        sent_args = self._deprecated_messages_sent.setdefault(msg, list())

        if args in sent_args:
            # Already logged this message, so don't log it again.
            return

        sent_args.append(args)
        self.warn(stdmsg, *args, **kwargs)

    def process(self, msg, kwargs):
        # NOTE(jecarey): If msg is not unicode, coerce it into unicode
        #                before it can get to the python logging and
        #                possibly cause string encoding trouble
        if not isinstance(msg, six.text_type):
            msg = six.text_type(msg)

        if 'extra' not in kwargs:
            kwargs['extra'] = {}
        extra = kwargs['extra']

        context = kwargs.pop('context', None)
        if not context:
            context = getattr(store, 'context', None)
        if context:
            extra.update(_dictify_context(context))

        instance = kwargs.pop('instance', None)
        instance_uuid = (extra.get('instance_uuid') or
                         kwargs.pop('instance_uuid', None))
        instance_extra = ''
        if instance:
            instance_extra = CONF.instance_format % instance
        elif instance_uuid:
            instance_extra = (CONF.instance_uuid_format
                              % {'uuid': instance_uuid})
        extra['instance'] = instance_extra

        extra.setdefault('user_identity', kwargs.pop('user_identity', None))

        extra['project'] = self.project
        extra['version'] = self.version
        extra['extra'] = extra.copy()
        return msg, kwargs


class JSONFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None):
        # NOTE(jkoelker) we ignore the fmt argument, but its still there
        #                since logging.config.fileConfig passes it.
        self.datefmt = datefmt

    def formatException(self, ei, strip_newlines=True):
        lines = traceback.format_exception(*ei)
        if strip_newlines:
            lines = [moves.filter(
                lambda x: x,
                line.rstrip().splitlines()) for line in lines]
            lines = list(itertools.chain(*lines))
        return lines

    def format(self, record):
        message = {'message': record.getMessage(),
                   'asctime': self.formatTime(record, self.datefmt),
                   'name': record.name,
                   'msg': record.msg,
                   'args': record.args,
                   'levelname': record.levelname,
                   'levelno': record.levelno,
                   'pathname': record.pathname,
                   'filename': record.filename,
                   'module': record.module,
                   'lineno': record.lineno,
                   'funcname': record.funcName,
                   'created': record.created,
                   'msecs': record.msecs,
                   'relative_created': record.relativeCreated,
                   'thread': record.thread,
                   'thread_name': record.threadName,
                   'process_name': record.processName,
                   'process': record.process,
                   'traceback': None}

        if hasattr(record, 'extra'):
            message['extra'] = record.extra

        if record.exc_info:
            message['traceback'] = self.formatException(record.exc_info)

        return jsonutils.dumps(message)


_loggers = {}


def getLogger(name='unknown', version='unknown'):
    if name not in _loggers:
        _loggers[name] = ContextAdapter(logging.getLogger(name),
                                        name,
                                        version)
    return _loggers[name]


def getLazyLogger(name='unknown', version='unknown'):
    """Returns lazy logger.

    Creates a pass-through logger that does not create the real logger
    until it is really needed and delegates all calls to the real logger
    once it is created.
    """
    return LazyAdapter(name, version)

