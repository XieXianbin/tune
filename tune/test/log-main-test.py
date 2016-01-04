import os,sys
import argparse
lib_path = os.path.abspath(os.path.join('..'))
sys.path.append(lib_path)

from tune.common import log
from tune.test import log_test

logging = log.getLogger()

def test():
    logging.info("abc")
    log_test.test()

test()


