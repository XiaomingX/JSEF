import json
import os
import re
import time
import importlib
import traceback
import argparse
from utils.process import AutoProcess


def parse_targets(targets):
    parsed = {}
    for target in targets:
        if os.path.isfile(target):
            with open(target) as f:
                lines = f.read().splitlines()
        else:
            lines = [target]
        
        for line in lines:
            match = re.search(r'^([\w.\-]{,80})([ :](\d{,5}))?$', line.strip())
            if match:
                port = match.group(3) or '7001'
                host = match.group(1)
                parsed[f"{host}:{port}"] = {'ip': host, 'port': port}
    return parsed

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--targets', required=True, nargs='+', help='target, or targets file. eg. 127.0.0.1:7001')
    parser.add_argument('-v', '--vulnerability', nargs='+', help='vulnerability name. eg. "CVE-2020-14750 cve_2014_4210 console"')
    parser.add_argument('-p', '--process_number', default=8, type=int, help='Number of processes (default 8).')
    parser.add_argument('-o', '--output', required=False, type=str, help='Path to json output.')
    parser.add_argument('-s', '--ssl', action='store_true', help='Force SSL.')
    args = parser.parse_args()

    s_time = time.time()
    if args.output and not os.path.isdir(args.output):
        os.makedirs(args.output)
    
    vulnerability_list = {v.lower().replace('-', '_') for v in (args.vulnerability or [])}
    m_target = parse_targets(args.targets)

    autopro = AutoProcess(args.process_number)
    autopro.run()

    for filename in os.listdir('./stars'):
        match = re.search(r'([^\.\/\\]+)\.py', filename)
        if not match or filename.startswith('_'):
            continue
        
        script_name = match.group(1)
        if vulnerability_list and script_name not in vulnerability_list:
            continue

        try:
            module = importlib.import_module(f'.{script_name}', 'stars')
            if 'run' not in dir(module):
                continue
            
            for key, info in m_target.items():
                data = {'IP': info['ip'], 'PORT': info['port'], 'IS_SSL': args.ssl or None}
                autopro.put_task(module.run, [data], queue=True)
        except Exception:
            print(f"Error loading {script_name}:\n{traceback.format_exc()}")

    while autopro.signal > 0:
        for ret in autopro.get_return():
            for key, info in m_target.items():
                if info['ip'] == ret['IP'] and info['port'] == ret['PORT']:
                    m_target[key][ret['NAME']] = ret['STATE']
        time.sleep(1)

    if args.output:
        ts = time.strftime("%m%d_%H%M%S")
        with open(os.path.join(args.output, f'result_{ts}.json'), 'w') as f:
            json.dump(m_target, f, indent=4)
    
    print(f'Run completed in {int(time.time() - s_time)} seconds.')
