// gralloch Frida behavioral tracer (stage 5).
//
// RUN THIS ONLY INSIDE THE ANALYSIS VM, on an active snapshot, with the network
// off or faked (FakeNet-NG). It EXECUTES the sample — never run it on the host.
//
// It hooks common Windows APIs and emits one structured event per call as a
// `send()` message: { t:"gralloch", cat, api, detail }. The run-frida.py runner
// (or a Frida MCP) collects these into trace.json, which the host-side
// `dynamic_import` tool then normalizes. Keep hooks in try/catch so a missing
// export never aborts the session.

'use strict';

function emit(cat, api, detail) {
  try { send({ t: 'gralloch', cat: cat, api: api, detail: String(detail) }); } catch (e) {}
}

function wstr(p) { try { return p.isNull() ? '' : p.readUtf16String(); } catch (e) { return ''; } }
function astr(p) { try { return p.isNull() ? '' : p.readAnsiString(); } catch (e) { return ''; } }

// [module, export, category, argReader(args) -> detail string]
const HOOKS = [
  ['kernel32.dll', 'CreateFileW', 'filesystem', a => wstr(a[0])],
  ['kernel32.dll', 'CreateFileA', 'filesystem', a => astr(a[0])],
  ['kernel32.dll', 'DeleteFileW', 'filesystem', a => wstr(a[0])],
  ['kernel32.dll', 'CopyFileW', 'filesystem', a => wstr(a[0]) + ' -> ' + wstr(a[1])],
  ['kernel32.dll', 'MoveFileW', 'filesystem', a => wstr(a[0]) + ' -> ' + wstr(a[1])],

  ['advapi32.dll', 'RegCreateKeyExW', 'registry', a => wstr(a[1])],
  ['advapi32.dll', 'RegOpenKeyExW', 'registry', a => wstr(a[1])],
  ['advapi32.dll', 'RegSetValueExW', 'registry', a => wstr(a[1])],

  ['ws2_32.dll', 'connect', 'network', a => sockaddr(a[1])],
  ['ws2_32.dll', 'WSAConnect', 'network', a => sockaddr(a[1])],
  ['wininet.dll', 'InternetOpenUrlW', 'network', a => wstr(a[1])],
  ['wininet.dll', 'InternetConnectW', 'network', a => wstr(a[1])],
  ['winhttp.dll', 'WinHttpConnect', 'network', a => wstr(a[1])],

  ['kernel32.dll', 'CreateProcessW', 'process', a => wstr(a[0]) || wstr(a[1])],
  ['kernel32.dll', 'CreateProcessA', 'process', a => astr(a[0]) || astr(a[1])],
  ['kernel32.dll', 'WinExec', 'process', a => astr(a[0])],
  ['shell32.dll', 'ShellExecuteW', 'process', a => wstr(a[2]) + ' ' + wstr(a[3])],

  ['kernel32.dll', 'VirtualAllocEx', 'memory', a => 'size=' + a[2].toInt32()],
  ['kernel32.dll', 'WriteProcessMemory', 'memory', a => 'size=' + a[3].toInt32()],
  ['kernel32.dll', 'CreateRemoteThread', 'memory', a => 'start=' + a[3]],

  ['kernel32.dll', 'LoadLibraryW', 'module', a => wstr(a[0])],
  ['kernel32.dll', 'LoadLibraryA', 'module', a => astr(a[0])],

  ['kernel32.dll', 'IsDebuggerPresent', 'anti-analysis', () => 'IsDebuggerPresent'],
  ['kernel32.dll', 'CheckRemoteDebuggerPresent', 'anti-analysis', () => 'CheckRemoteDebuggerPresent'],
];

function sockaddr(p) {
  // sockaddr_in: family(2) port(2, be) addr(4)
  try {
    const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
    const ip = p.add(4).readU8() + '.' + p.add(5).readU8() + '.' + p.add(6).readU8() + '.' + p.add(7).readU8();
    return ip + ':' + port;
  } catch (e) { return '<sockaddr>'; }
}

let installed = 0;
for (const [mod, exp, cat, reader] of HOOKS) {
  try {
    const addr = Module.getExportByName(mod, exp);
    Interceptor.attach(addr, {
      onEnter(args) {
        let detail = '';
        try { detail = reader(args); } catch (e) {}
        emit(cat, exp, detail);
      },
    });
    installed++;
  } catch (e) {
    // export not present in this image; skip quietly
  }
}
emit('meta', 'ready', installed + ' hooks installed');
