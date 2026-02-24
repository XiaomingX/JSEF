import datetime
import logging
import sys
import warnings

APPNAME = 'weblogicscanner'
LOG_LEVEL = logging.INFO

logger = logging.getLogger(APPNAME)

formatter = logging.Formatter(
    '[%(asctime)s][%(levelname)s] %(message)s', datefmt='%H:%M:%S')
file_handler = logging.FileHandler('%s_%s.log' % (APPNAME, datetime.datetime.now().strftime('%Y%m%d')),
                                   encoding='utf-8')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.formatter = formatter
logger.addHandler(console_handler)

logger.setLevel(LOG_LEVEL)

warnings.filterwarnings('ignore')
