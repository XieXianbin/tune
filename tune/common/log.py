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


# configure for log
log_config_append=None
log_dir="./"
log_file="D://tune.log"
use_stderr=False
publish_errors=False
log_date_format = "%Y-%m-%d %H:%M:%S"
log_format=None
debug=True
verbose=True
default_log_levels={}
use_syslog=False
#logging_default_format_string="%(asctime)s.%(msecs)03d %(process)d %(levelname)s %(name)s %(funcName)s %(pathname)s:%(lineno)d [-] %(instance)s%(message)s"
logging_default_format_string="%(asctime)s.%(msecs)03d %(process)d %(levelname)s %(pathname)s:%(lineno)d %(funcName)s [-] %(instance)s%(message)s"
logging_context_format_string="%(asctime)s.%(msecs)03d %(process)d %(levelname)s [%(request_id)s %(user)s %(tenant)s] %(instance)s%(message)s"
logging_exception_prefix="%(asctime)s.%(msecs)03d %(process)d TRACE %(instance)s"
logging_debug_format_suffix="%(funcName)s %(pathname)s:%(lineno)d"


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


def _get_log_file_path(binary=None):
    logfile = log_file
    logdir = log_dir

    if logfile and not logdir:
        return logfile

    if logfile and logdir:
        return os.path.join(logdir, logfile)

    if logdir:
        binary = binary or _get_binary_name()
        return '%s.log' % (os.path.join(logdir, binary),)

    return None


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


class LogConfigError(Exception):

    message = 'Error loading logging config %(log_config)s: %(err_msg)s'

    def __init__(self, log_config, err_msg):
        self.log_config = log_config
        self.err_msg = err_msg

    def __str__(self):
        return self.message % dict(log_config=self.log_config,
                                   err_msg=self.err_msg)


def _load_log_config(log_config_append):
    try:
        logging.config.fileConfig(log_config_append,
                                  disable_existing_loggers=False)
    except (moves.configparser.Error, KeyError) as exc:
        raise LogConfigError(log_config_append, six.text_type(exc))


def _create_logging_excepthook(product_name):
    def logging_excepthook(exc_type, value, tb):
        extra = {'exc_info': (exc_type, value, tb)}
        getLogger(product_name).critical(
            "".join(traceback.format_exception_only(exc_type, value)),
            **extra)
    return logging_excepthook


def setup(product_name, version='unknown'):
    """Setup logging."""
    if log_config_append:
        _load_log_config(CONF.log_config_append)
    else:
        _setup_logging_from_conf(product_name, version)
    sys.excepthook = _create_logging_excepthook(product_name)


def _setup_logging_from_conf(project, version):
    log_root = getLogger(None).logger
    for handler in log_root.handlers:
        log_root.removeHandler(handler)

    logpath = _get_log_file_path()
    if logpath:
        filelog = logging.handlers.WatchedFileHandler(logpath)
        log_root.addHandler(filelog)

    if use_stderr:
        streamlog = ColorHandler()
        log_root.addHandler(streamlog)

    elif not logpath:
        # pass sys.stdout as a positional argument
        # python2.6 calls the argument strm, in 2.7 it's stream
        streamlog = logging.StreamHandler(sys.stdout)
        log_root.addHandler(streamlog)

    if publish_errors:
        try:
            handler = importutils.import_object(
                "nova.openstack.common.log_handler.PublishErrorsHandler",
                logging.ERROR)
        except ImportError:
            handler = importutils.import_object(
                "oslo.messaging.notify.log_handler.PublishErrorsHandler",
                logging.ERROR)
        log_root.addHandler(handler)

    datefmt = log_date_format
    for handler in log_root.handlers:
        # NOTE(alaski): CONF.log_format overrides everything currently.  This
        # should be deprecated in favor of context aware formatting.
        if log_format:
            handler.setFormatter(logging.Formatter(fmt=CONF.log_format,
                                                   datefmt=datefmt))
            log_root.info('Deprecated: log_format is now deprecated and will '
                          'be removed in the next release')
        else:
            handler.setFormatter(ContextFormatter(project=project,
                                                  version=version,
                                                  datefmt=datefmt))

    if debug:
        log_root.setLevel(logging.DEBUG)
    elif verbose:
        log_root.setLevel(logging.INFO)
    else:
        log_root.setLevel(logging.WARNING)

    for pair in default_log_levels:
        mod, _sep, level_name = pair.partition('=')
        logger = logging.getLogger(mod)
        # NOTE(AAzza) in python2.6 Logger.setLevel doesn't convert string name
        # to integer code.
        if sys.version_info < (2, 7):
            level = logging.getLevelName(level_name)
            logger.setLevel(level)
        else:
            logger.setLevel(level_name)

    if use_syslog:
        try:
            facility = _find_facility_from_conf()
            # TODO(bogdando) use the format provided by RFCSysLogHandler
            #   after existing syslog format deprecation in J
            if CONF.use_syslog_rfc_format:
                syslog = RFCSysLogHandler(facility=facility)
            else:
                syslog = logging.handlers.SysLogHandler(facility=facility)
            log_root.addHandler(syslog)
        except socket.error:
            log_root.error('Unable to add syslog handler. Verify that syslog '
                           'is running.')


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


class ContextFormatter(logging.Formatter):
    """A context.RequestContext aware formatter configured through flags.

    The flags used to set format strings are: logging_context_format_string
    and logging_default_format_string.  You can also specify
    logging_debug_format_suffix to append extra formatting if the log level is
    debug.

    For information about what variables are available for the formatter see:
    http://docs.python.org/library/logging.html#formatter

    If available, uses the context value stored in TLS - local.store.context

    """

    def __init__(self, *args, **kwargs):
        """Initialize ContextFormatter instance

        Takes additional keyword arguments which can be used in the message
        format string.

        :keyword project: project name
        :type project: string
        :keyword version: project version
        :type version: string

        """

        self.project = kwargs.pop('project', 'unknown')
        self.version = kwargs.pop('version', 'unknown')

        logging.Formatter.__init__(self, *args, **kwargs)

    def format(self, record):
        """Uses contextstring if request_id is set, otherwise default."""

        # NOTE(jecarey): If msg is not unicode, coerce it into unicode
        #                before it can get to the python logging and
        #                possibly cause string encoding trouble
        if not isinstance(record.msg, six.text_type):
            record.msg = six.text_type(record.msg)

        # store project info
        record.project = self.project
        record.version = self.version

        # store request info
        context = getattr(store, 'context', None)
        if context:
            d = _dictify_context(context)
            for k, v in d.items():
                setattr(record, k, v)

        # NOTE(sdague): default the fancier formatting params
        # to an empty string so we don't throw an exception if
        # they get used
        for key in ('instance', 'color', 'user_identity'):
            if key not in record.__dict__:
                record.__dict__[key] = ''

        if record.__dict__.get('request_id'):
            fmt = logging_context_format_string
        else:
            fmt = logging_default_format_string

        if (record.levelno == logging.DEBUG and
                logging_debug_format_suffix):
            fmt += " " + logging_debug_format_suffix

        if sys.version_info < (3, 2):
            self._fmt = fmt
        else:
            self._style = logging.PercentStyle(fmt)
            self._fmt = self._style._fmt
        # Cache this on the record, Logger will respect our formatted copy
        if record.exc_info:
            record.exc_text = self.formatException(record.exc_info, record)
        return logging.Formatter.format(self, record)

    def formatException(self, exc_info, record=None):
        """Format exception output with logging_exception_prefix."""
        if not record:
            return logging.Formatter.formatException(self, exc_info)

        stringbuffer = moves.StringIO()
        traceback.print_exception(exc_info[0], exc_info[1], exc_info[2],
                                  None, stringbuffer)
        lines = stringbuffer.getvalue().split('\n')
        stringbuffer.close()

        if logging_exception_prefix.find('%(asctime)') != -1:
            record.asctime = self.formatTime(record, self.datefmt)

        formatted_lines = []
        for line in lines:
            pl = logging_exception_prefix % record.__dict__
            fl = '%s%s' % (pl, line)
            formatted_lines.append(fl)
        return '\n'.join(formatted_lines)


setup("tune")


