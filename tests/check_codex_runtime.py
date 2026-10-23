"""Check the installed plugin through Codex, without a model turn or sample execution.

Pass an isolated, already installed --codex-home and an --output outside the repo.
This verifies native startup and MCP tool contracts. It does not test the model's
interpretation of a chat command or execute the external analyzers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codex-home', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sample', type=Path, required=True, help='Benign PE, read but never executed')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(Path(__file__).resolve().parents[1]):
        parser.error('--output must be outside the source repository')
    output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CODEX_HOME=str(args.codex_home.resolve()))
    with (output / 'app-server.log').open('w', encoding='utf-8') as log:
        proc = subprocess.Popen(['codex', 'app-server', '--stdio'], cwd=output, env=env,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
        inbox = queue.Queue()
        def receive():
            for line in proc.stdout:
                inbox.put(json.loads(line))
        threading.Thread(target=receive, daemon=True).start()
        sequence = 0
        def rpc(method, params):
            nonlocal sequence
            sequence += 1
            proc.stdin.write((json.dumps({'id': sequence, 'method': method, 'params': params}) + '\n').encode())
            proc.stdin.flush()
            while True:
                message = inbox.get(timeout=60)
                if message.get('id') == sequence:
                    if 'error' in message:
                        raise RuntimeError(message['error'])
                    return message['result']
        results = []
        try:
            rpc('initialize', {'clientInfo': {'name': 'gralloch-runtime-check', 'version': '1'}})
            proc.stdin.write(b'{"method":"initialized"}\n')
            proc.stdin.flush()
            listed = rpc('skills/list', {'cwds': [str(output)], 'forceReload': True})
            assert any(s['name'] == 'gralloch:gralloch' and s['enabled']
                       for entry in listed['data'] for s in entry['skills']), listed
            thread = rpc('thread/start', {'cwd': str(output), 'ephemeral': True})['thread']['id']
            status = rpc('mcpServerStatus/list', {'threadId': thread})
            server = next(s for s in status['data'] if s.get('pluginId') == 'gralloch@gralloch-codex')
            assert server['runtimeStatus'] == 'connected', server
            expected = {'case_new', 'triage', 'capa_import', 'yara_scan', 'deobfuscate', 'dynamic_import', 'call_graph', 'function_card', 'verify', 'report'}
            assert set(server['tools']) == expected, server
            def tool(name, arguments):
                result = rpc('mcpServer/tool/call', {'threadId': thread, 'server': server['name'],
                                                    'tool': name, 'arguments': arguments})
                results.append({'tool': name, 'result': result})
                assert not result.get('isError'), (name, result)
                return result
            cases = output / ('cases with spaces ' + uuid.uuid4().hex[:8])
            tool('case_new', {'sample_path': str(args.sample.resolve()), 'cases_root': str(cases)})
            sha = hashlib.sha256(args.sample.read_bytes()).hexdigest()
            case = cases / sha[:16]
            tool('triage', {'case_dir': str(case)})
            tool('deobfuscate', {'case_dir': str(case)})
            # Explicit parser fixtures: no invented observed capabilities/behavior.
            (case / 'artifacts/capa.json').write_text(json.dumps({'meta': {'version': 'test-fixture'}, 'rules': {}}), 'utf-8')
            tool('capa_import', {'case_dir': str(case)})
            trace = output / 'synthetic-trace.json'
            trace.write_text(json.dumps({'tool': 'synthetic-test-fixture', 'events': []}), 'utf-8')
            tool('dynamic_import', {'case_dir': str(case), 'trace_path': str(trace)})
            (case / 'hypotheses.json').write_text('[]', 'utf-8')
            tool('verify', {'case_dir': str(case)})
            yara = rpc('mcpServer/tool/call', {'threadId': thread, 'server': server['name'],
                                             'tool': 'yara_scan', 'arguments': {'case_dir': str(case)}})
            if yara.get('isError'):
                assert 'without the `yara` feature' in str(yara), yara
                print('SKIP: YARA engine not compiled in')
            results.append({'tool': 'yara_scan', 'result': yara})
            cg = rpc('mcpServer/tool/call', {'threadId': thread, 'server': server['name'],
                                             'tool': 'call_graph', 'arguments': {'case_dir': str(case)}})
            if cg.get('isError'):
                assert 'ghidra_export.json' in str(cg), cg
                print('SKIP: no Ghidra export for call_graph')
            results.append({'tool': 'call_graph', 'result': cg})
            fc = rpc('mcpServer/tool/call', {'threadId': thread, 'server': server['name'],
                                             'tool': 'function_card', 'arguments': {'case_dir': str(case), 'function': '0x0'}})
            if fc.get('isError'):
                assert 'ghidra_export.json' in str(fc), fc
                print('SKIP: no Ghidra export for function_card')
            results.append({'tool': 'function_card', 'result': fc})
            tool('report', {'case_dir': str(case)})
            assert not json.loads((case / 'artifacts/report.json').read_text('utf-8'))['findings']['confirmed']
            print('PASS: command discovery, native MCP startup, 10 tool contracts, paths with spaces')
        finally:
            (output / 'runtime-results.json').write_text(json.dumps(results, indent=2), 'utf-8')
            proc.terminate()
            proc.wait(timeout=10)


if __name__ == '__main__':
    main()
