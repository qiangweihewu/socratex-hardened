#!/usr/bin/env python3
"""Share a TLS port (normally 443) between nginx's websites and TLS proxies.

nginx's stream module reads the server name (SNI) from each TLS ClientHello
without decrypting anything and forwards the whole connection: proxy domains
go to their proxy, everything else to nginx's own HTTPS servers, which move to
127.0.0.1:<site port>. Visitors' addresses reach the websites through the
PROXY protocol (set_real_ip_from / real_ip_header are added to the moved
servers).

Changes to existing nginx files are kept to the minimum: the `listen` lines
for the port (in whichever files they are) and one `include` line appended to
the main configuration file. Each such file is shown as a diff and needs its
own confirmation in a terminal; declining any of them changes nothing. Every
edited line carries a marker holding the original text, so `remove` restores
exactly those lines and leaves later edits to the files alone.

Exit status: 0 done, 1 error (nothing changed), 3 a file change was declined.

Usage (as root):
  nginx_sni.py status
  nginx_sni.py plan   --domain D --backend 127.0.0.1:PORT --owner NAME
  nginx_sni.py add    --domain D --backend 127.0.0.1:PORT --owner NAME
  nginx_sni.py remove --owner NAME [--domain D]
Options for unusual setups and tests: --port (default 443), --nginx-bin and
--nginx-conf (skip detecting the running nginx), SX_SNI_DIR (state directory,
default /etc/sx-sni).
"""
import argparse
import difflib
import glob
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

STATE_DIR = os.environ.get('SX_SNI_DIR', '/etc/sx-sni')
STATE_FILE = os.path.join(STATE_DIR, 'state.json')
STREAM_CONF = os.path.join(STATE_DIR, 'stream.conf')
ORIG = '#sx-sni-orig#'    # edited line: <new directives> #sx-sni-orig#<original line>
ADDED = '#sx-sni-added#'  # line added by this tool; removed on revert
SOCKET_OPTS = ('default_server', 'default', 'backlog=', 'rcvbuf=', 'sndbuf=', 'setfib=', 'fastopen=',
               'accept_filter=', 'deferred', 'bind', 'reuseport', 'so_keepalive=')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$')


class Fail(Exception):
    pass


def info(msg):
    try:
        print(f'==> {msg}', flush=True)
    except OSError:  # the terminal went away (e.g. SSH dropped): keep working
        pass


def warn(msg):
    try:
        print(f'WARNING: {msg}', file=sys.stderr, flush=True)
    except OSError:
        pass


def proc_cmdline(pid):
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            return f.read().replace(b'\0', b' ').decode(errors='replace').strip()
    except OSError:
        return ''


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    return p.returncode, p.stdout


# ---------- nginx configuration parser ----------
class Directive:
    __slots__ = ('name', 'args', 'file', 'line', 'end_line', 'start', 'end', 'ctx', 'block')

    def __repr__(self):
        return f'{self.name} {" ".join(self.args)} ({self.file}:{self.line})'


def tokenize(text, path):
    """Tokens (kind, value, start, end, line); kind is 'word', '{', '}' or ';'."""
    toks, i, n, line = [], 0, len(text), 1
    while i < n:
        c = text[i]
        if c == '\n':
            line += 1; i += 1; continue
        if c.isspace():
            i += 1; continue
        if c == '#':
            j = text.find('\n', i)
            i = n if j < 0 else j; continue
        if c in '{};':
            toks.append((c, c, i, i + 1, line)); i += 1; continue
        start, sline, buf = i, line, []
        if c in '"\'':
            i += 1
            while i < n and text[i] != c:
                if text[i] == '\\' and i + 1 < n:
                    buf.append(text[i:i + 2]); i += 2; continue
                if text[i] == '\n':
                    line += 1
                buf.append(text[i]); i += 1
            if i >= n:
                raise Fail(f'{path}:{sline}: unterminated quote')
            i += 1
        else:
            while i < n and not text[i].isspace() and text[i] not in ';{}':
                if text[i] == '\\' and i + 1 < n:
                    buf.append(text[i:i + 2]); i += 2; continue
                if text[i] == '$' and i + 1 < n and text[i + 1] == '{':  # ${var}
                    j = text.find('}', i)
                    if j < 0:
                        raise Fail(f'{path}:{line}: unterminated ${{')
                    buf.append(text[i:j + 1]); i = j + 1; continue
                buf.append(text[i]); i += 1
        toks.append(('word', ''.join(buf), start, i, sline))
    return toks


class Config:
    """The configuration tree nginx loads, following include directives."""

    def __init__(self, main):
        self.main = os.path.abspath(main)
        self.prefix = os.path.dirname(self.main)
        self.texts = {}   # path -> file text
        self.order = []   # files in load order
        self.tree = self._parse_file(self.main, [], 0)

    def _parse_file(self, path, ctx, depth):
        if depth > 32:
            raise Fail(f'include nesting too deep at {path}')
        try:
            with open(path, encoding='utf-8', newline='') as f:
                text = f.read()
        except (OSError, UnicodeDecodeError) as e:
            raise Fail(f'cannot read {path}: {e}')
        if path not in self.texts:
            self.order.append(path)
        self.texts[path] = text
        if '_by_lua_block' in text:
            raise Fail(f'{path} contains Lua blocks, which this tool cannot parse safely; '
                       'set up the SNI routing by hand (see the README)')
        toks = tokenize(text, path)
        out, i = self._parse_block(toks, 0, path, ctx, depth, top=True)
        return out

    def _parse_block(self, toks, i, path, ctx, depth, top):
        out, words = [], []
        while i < len(toks):
            kind, _, start, end, line = toks[i]
            if kind == 'word':
                words.append(toks[i]); i += 1; continue
            if kind == '}':
                if top or words:
                    raise Fail(f'{path}:{line}: unexpected "}}"')
                return out, i + 1
            if not words:
                raise Fail(f'{path}:{line}: unexpected "{kind}"')
            d = Directive()
            d.name, d.args = words[0][1], [w[1] for w in words[1:]]
            d.file, d.line, d.start, d.ctx, d.block = path, words[0][4], words[0][2], list(ctx), None
            words = []
            if kind == ';':
                d.end, d.end_line = end, line
                out.append(d); i += 1
                if d.name == 'include' and d.args:
                    pattern = d.args[0] if os.path.isabs(d.args[0]) else os.path.join(self.prefix, d.args[0])
                    for f in sorted(glob.glob(pattern)):
                        out.extend(self._parse_file(os.path.abspath(f), ctx, depth + 1))
                continue
            d.end, d.end_line = end, line   # the opening brace
            d.block, i = self._parse_block(toks, i + 1, path, ctx + [d.name], depth, top=False)
            out.append(d)
        if not top:
            raise Fail(f'{path}: missing "}}"')
        return out, i

    def walk(self, nodes=None):
        for d in self.tree if nodes is None else nodes:
            yield d
            if d.block is not None:
                yield from self.walk(d.block)


def split_listen(arg):
    """'443' -> ('*', 443); '[::]:443' -> ('[::]', 443); 'unix:...' -> None."""
    if arg.startswith('unix:'):
        return None
    if arg.startswith('['):
        host, _, rest = arg[1:].partition(']')
        port = rest[1:] if rest.startswith(':') else '80'
        host = f'[{host}]'
    elif arg.isdigit():
        host, port = '*', arg
    else:
        host, sep, port = arg.rpartition(':')
        if not sep:
            host, port = arg, '80'
    if host == '0.0.0.0':
        host = '*'
    return (host, int(port)) if port.isdigit() else None


def socket_opt(p):
    return any(p == o or (o.endswith('=') and p.startswith(o)) for o in SOCKET_OPTS)


# ---------- the running nginx ----------
class Nginx:
    def __init__(self, a, state):
        self.unit = None
        if a.nginx_bin or a.nginx_conf:
            if not (a.nginx_bin and a.nginx_conf):
                raise Fail('--nginx-bin and --nginx-conf go together')
            self.bin, self.conf = a.nginx_bin, os.path.abspath(a.nginx_conf)
        elif state and state.get('nginx_bin'):
            self.bin, self.conf, self.unit = state['nginx_bin'], state['nginx_conf'], state.get('nginx_unit')
        else:
            self._detect()
        rc, self.V = run([self.bin, '-V'])
        if rc != 0:
            raise Fail(f'{self.bin} -V failed: {self.V.strip()}')

    def _detect(self):
        masters = []
        for pid in filter(str.isdigit, os.listdir('/proc')):
            cmd = proc_cmdline(pid)
            if cmd.startswith('nginx: master process'):
                masters.append((pid, cmd))
        if not masters:
            raise Fail('nginx is not running')
        if len(masters) > 1:
            raise Fail('more than one nginx master process is running; pass --nginx-bin and --nginx-conf')
        pid, cmd = masters[0]
        exe = os.readlink(f'/proc/{pid}/exe')
        self.bin = exe[:-len(' (deleted)')] if exe.endswith(' (deleted)') else exe
        parts = cmd[len('nginx: master process'):].split()
        conf = parts[parts.index('-c') + 1] if '-c' in parts[:-1] else None
        if not conf:
            _, v = run([self.bin, '-V'])
            m = re.search(r'--conf-path=(\S+)', v)
            p = re.search(r'--prefix=(\S+)', v)
            conf = m.group(1) if m else os.path.join(p.group(1) if p else '/usr/local/nginx', 'conf/nginx.conf')
        self.conf = os.path.abspath(conf)
        try:
            with open(f'/proc/{pid}/cgroup') as f:
                m = re.search(r'system\.slice/([^/\s]+\.service)', f.read())
            self.unit = m.group(1) if m else None
        except OSError:
            pass

    def test(self):
        return run([self.bin, '-t', '-c', self.conf])

    def _master(self):
        masters = []
        for pid in filter(str.isdigit, os.listdir('/proc') if os.path.isdir('/proc') else []):
            cmd = proc_cmdline(pid)
            if cmd.startswith('nginx: master process'):
                masters.append((pid, cmd))
        mine = [p for p, c in masters if f'-c {self.conf}' in c] or ([masters[0][0]] if len(masters) == 1 else [])
        return mine[0] if len(mine) == 1 else None

    def _workers(self, master):
        out = set()
        for pid in filter(str.isdigit, os.listdir('/proc')):
            try:
                with open(f'/proc/{pid}/stat') as f:
                    ppid = f.read().rsplit(')', 1)[1].split()[1]
            except (OSError, IndexError):
                continue
            if ppid == master and proc_cmdline(pid) == 'nginx: worker process':
                out.add(pid)
        return out

    def reload(self):
        """Reload and wait until the new workers serve: a configuration that nginx -t accepts can
        still fail to apply (e.g. a port that cannot be bound), and then the old workers stay."""
        master = self._master()
        old = self._workers(master) if master else set()
        rc, out = run(['systemctl', 'reload', self.unit]) if self.unit else run([self.bin, '-c', self.conf, '-s', 'reload'])
        if rc != 0:
            raise Fail(f'reloading nginx failed: {out.strip()}')
        if not old:
            time.sleep(2)
            return
        deadline = time.time() + 15
        while time.time() < deadline:
            now = self._workers(master)
            if now and not (now & old):
                return
            time.sleep(0.3)
        raise Fail('nginx did not apply the new configuration within 15 s (see its error log)')


# ---------- state ----------
def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def write_atomic(path, text, like=None, mode=0o644):
    """Replace a file's content atomically. Symlinks (sites-enabled -> sites-available) are followed,
    so the link stays a link; the temporary name starts with a dot, which `include dir/*` skips."""
    real = os.path.realpath(path)
    d, b = os.path.split(real)
    tmp = os.path.join(d, f'.{b}.sx-sni-tmp')
    with open(tmp, 'w', encoding='utf-8', newline='') as f:
        f.write(text)
    like = os.path.realpath(like) if like else None
    if like and os.path.exists(like):
        st = os.stat(like)
        os.chmod(tmp, st.st_mode & 0o7777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass
    else:
        os.chmod(tmp, mode)
    os.replace(tmp, real)


def save_state(state):
    os.makedirs(STATE_DIR, mode=0o755, exist_ok=True)
    write_atomic(STATE_FILE, json.dumps(state, indent=2) + '\n', mode=0o600)


def stream_conf(state):
    pp, routes = state['proxy_protocol'], state['routes']
    out = [f'# Generated by nginx_sni.py (socratex deploy scripts): port {state["port"]} is shared by TLS SNI.',
           '# Do not edit by hand. Show: nginx_sni.py status. Undo: nginx_sni.py remove --owner NAME.',
           'stream {',
           '    map $ssl_preread_server_name $sx_sni_upstream {']
    for r in routes:
        out.append(f'        {r["domain"]} {"127.0.0.1:%d" % r["hop"] if pp else r["backend"]};  # {r["owner"]}')
    out += [f'        default 127.0.0.1:{state["site_port"]};  # nginx websites',
            '    }',
            '    server {']
    out += [f'        listen {spec};' for spec in state['listen']]
    out += ['        ssl_preread on;']
    if pp:
        out += ['        proxy_protocol on;  # websites see the visitor address (real_ip_header proxy_protocol)']
    out += ['        proxy_pass $sx_sni_upstream;', '        proxy_timeout 1h;', '    }']
    if pp:
        for r in routes:  # proxies do not speak the PROXY protocol: accept it here, forward plain TLS
            out += ['    server {', f'        listen 127.0.0.1:{r["hop"]} proxy_protocol;',
                    f'        proxy_pass {r["backend"]};', '        proxy_timeout 1h;', '    }']
    out.append('}')
    return '\n'.join(out) + '\n'


def spec_host(spec):
    first = spec.split()[0]
    return '*' if first.isdigit() else first.rpartition(':')[0]


def merge_spec(specs, spec):
    """One stream listen per address; an ipv6only= option wins over none."""
    for i, old in enumerate(specs):
        if spec_host(old) == spec_host(spec):
            if 'ipv6only=' in spec and 'ipv6only=' not in old:
                specs[i] = spec
            return
    specs.append(spec)


# ---------- helpers ----------
def port_free(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # like nginx: TIME_WAIT leftovers do not count
    try:
        s.bind(('127.0.0.1', port))
        s.listen(1)
        return True
    except OSError:
        return False
    finally:
        s.close()


def port_open(port, timeout=1.0):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout):
            return True
    except OSError:
        return False


def pick_port(start, taken):
    for p in range(start, start + 500):
        if p not in taken and port_free(p):
            taken.add(p)
            return p
    raise Fail(f'no free local port found from {start}')


def probe(names, port, addr):
    """HTTPS status code per site name, connecting to this machine at addr (127.0.0.1 or [::1])."""
    if not shutil.which('curl'):
        return {}
    res = {}
    for n in names:
        _, out = run(['curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '8',
                      '--resolve', f'{n}:{port}:{addr}', f'https://{n}:{port}/'])
        res[n] = out.strip()[-3:] or '000'
    return res


def ask(question):
    if not sys.stdin.isatty():
        return False
    try:
        return input(f'{question} [y/N] ').strip().lower() in ('y', 'yes')
    except EOFError:
        return False


def line_span(text, pos):
    ls = text.rfind('\n', 0, pos) + 1
    le = text.find('\n', pos)
    return ls, (len(text) if le < 0 else le)


# ---------- planning ----------
class Plan:
    def __init__(self):
        self.edits = {}       # path -> new text
        self.repls = {}       # path -> [(start, end, replacement)] in original offsets
        self.notes = {}       # path -> [what changes]
        self.sites = []       # site names to probe before / after
        self.warnings = []
        self.load_module = None


def make_plan(cfg, ngx, state, port, new_route):
    plan = Plan()
    V = ngx.V
    # Modules.
    m = re.search(r'--with-stream(=dynamic)?(?=\s|$)', V)
    if not m:
        raise Fail('this nginx was built without the stream module (nginx -V shows no --with-stream)')
    if '--with-stream_ssl_preread_module' not in V:
        raise Fail('this nginx was built without ngx_stream_ssl_preread_module, which reads the SNI')
    if m.group(1) and not any(d.name == 'load_module' and 'ngx_stream_module' in ' '.join(d.args) for d in cfg.walk()):
        mp = re.search(r'--modules-path=(\S+)', V)
        cands = [os.path.join(mp.group(1), 'ngx_stream_module.so')] if mp else []
        cands += [os.path.join(cfg.prefix, 'modules/ngx_stream_module.so'), '/usr/lib/nginx/modules/ngx_stream_module.so']
        so = next((c for c in cands if os.path.exists(c)), None)
        if not so:
            hint = ' (install it with: apt-get install libnginx-mod-stream)' if shutil.which('apt-get') else ''
            raise Fail(f'the nginx stream module is not installed{hint}')
        plan.load_module = so
    realip = '--with-http_realip_module' in V

    # Our include, and nobody else's stream block (nginx allows only one).
    ours = [d for d in cfg.tree if d.name == 'include' and d.args and d.args[0] == STREAM_CONF]
    others = [d for d in cfg.walk() if d.name == 'stream' and d.block is not None and d.file != STREAM_CONF]
    if others:
        d = others[0]
        raise Fail(f'nginx already has a stream {{}} block ({d.file}:{d.line}); only one is allowed, '
                   'so add the SNI routing to it by hand (see the README)')
    if ours and not state:
        raise Fail(f'{ours[0].file}:{ours[0].line} includes {STREAM_CONF} but {STATE_FILE} is missing; '
                   f'delete the line marked {ADDED} and run again')

    # HTTP servers on the shared port (and those already moved).
    http_rip = [d for d in cfg.walk() if d.name == 'real_ip_header' and d.ctx == ['http']]
    site_port = state['site_port'] if state else None
    moving, names_all, seen = [], set(), {}
    for srv in (d for d in cfg.walk() if d.name == 'server' and d.block is not None and d.ctx == ['http']):
        lst = []
        on_port = False
        for d in srv.block:
            if d.name != 'listen' or not d.args:
                continue
            hp = split_listen(d.args[0])
            if not hp:
                continue
            if hp[1] == port and not any(x in ('quic', 'http3') for x in d.args[1:]):
                where = f'{d.file}:{d.line}'
                if seen.setdefault((d.file, d.start), id(srv)) != id(srv):
                    raise Fail(f'{where}: this listen line is included into several server blocks, so editing it '
                               'would change all of them; give each server its own listen line and run again')
                if 'proxy_protocol' in d.args[1:]:
                    raise Fail(f'{where}: port {port} already receives the PROXY protocol (a load balancer in front?); '
                               'sharing it by SNI would break that, so set the routing up by hand')
                if hp[0] not in ('*', '[::]'):
                    raise Fail(f'{where}: listens on one address ({d.args[0]}); sites told apart by address cannot share '
                               'one local port, so set the routing up by hand (see the README)')
                lst.append((d, hp))
            if hp[1] in (port, site_port):
                on_port = True
        names = [a for d in srv.block if d.name == 'server_name' for a in d.args]
        if on_port or lst:
            names_all.update(n.lower() for n in names)
        if lst:
            moving.append((srv, lst, names))
    dom = new_route['domain'] if new_route else None
    if dom and dom in names_all:
        raise Fail(f'{dom} is a website on this nginx; give the proxy its own subdomain')

    pp = state['proxy_protocol'] if state else realip
    listen_specs = list(state['listen']) if state else []
    if moving:
        if not site_port:
            taken = {p for d in cfg.walk() if d.name == 'listen' and d.args
                     for p in [(split_listen(d.args[0]) or (None, None))[1]] if p}
            site_port = pick_port(10443, taken)
        if pp and any(d.args and d.args[0] != 'proxy_protocol' for d in http_rip):
            d = next(d for d in http_rip if d.args[0] != 'proxy_protocol')
            raise Fail(f'{d.file}:{d.line} sets real_ip_header {d.args[0]} for all sites; the moved sites would '
                       'need real_ip_header proxy_protocol. Set the SNI routing up by hand (see the README)')
        emitted = set()
        for srv, lst, names in moving:
            rip = [d for d in srv.block if d.name == 'real_ip_header']
            if pp and rip and rip[0].args and rip[0].args[0] != 'proxy_protocol':
                raise Fail(f'{rip[0].file}:{rip[0].line} sets real_ip_header {rip[0].args[0]}; the moved server '
                           'would need real_ip_header proxy_protocol. Set the SNI routing up by hand (see the README)')
            params = []
            for d, (host, _) in lst:
                text = cfg.texts[d.file]
                ls, le = line_span(text, d.start)
                rest = text[d.end:le].strip()
                if d.line != d.end_line or text[ls:d.start].strip() or (rest and not rest.startswith('#')):
                    raise Fail(f'{d.file}:{d.line}: this listen directive shares its line with other text or spans '
                               'several lines, so it cannot be edited safely; put it on a line of its own and run again')
                spec = f'{host}:{port}' if host != '*' else str(port)
                v6only = [p for p in d.args[1:] if p.startswith('ipv6only=')]
                if host.startswith('[') and v6only:
                    spec += ' ' + v6only[0]
                merge_spec(listen_specs, spec)
                for p in d.args[1:]:
                    if p.startswith('ipv6only=') or p == 'proxy_protocol' or p in params:
                        continue
                    if socket_opt(p):
                        key = p.split('=')[0]
                        if key in emitted:
                            continue
                        emitted.add(key)
                    params.append(p)
            if pp:
                params.append('proxy_protocol')
            new = f'listen 127.0.0.1:{site_port}{"".join(" " + p for p in params)};'
            if pp:
                new += ' set_real_ip_from 127.0.0.1;'
                if not rip and not http_rip:
                    new += ' real_ip_header proxy_protocol;'
            # Redirects nginx builds itself (trailing slash, relative return/rewrite) would name the local
            # port; without it they point at the public port again.
            label = next((n for n in names if n not in ('_', '""', '')), 'default server')
            other_ports = {hp[1] for d in srv.block if d.name == 'listen' and d.args
                           for hp in [split_listen(d.args[0])] if hp and hp[1] not in (port, 80)}
            if not any(d.name == 'port_in_redirect' for d in srv.block) and not other_ports:
                new += ' port_in_redirect off;'
            else:
                plan.warnings.append(f'server {label}: redirects nginx builds itself may name port {site_port}; '
                                     'check port_in_redirect there')
            for k, (d, _) in enumerate(lst):
                text = cfg.texts[d.file]
                ls, le = line_span(text, d.start)
                indent = text[ls:ls + len(text[ls:le]) - len(text[ls:le].lstrip())]
                orig = text[ls + len(indent):le]
                repl = f'{indent}{new} {ORIG}{orig}' if k == 0 else f'{indent}{ORIG}{orig}'
                plan.repls.setdefault(d.file, []).append((ls, le, repl))
            plan.notes.setdefault(lst[0][0].file, []).append(
                f'{len(lst)} listen line(s) of server {label} move to 127.0.0.1:{site_port}')
            plan.sites += [n for n in names if re.fullmatch(r'[A-Za-z0-9.-]+', n) and '.' in n][:1]
    for path, repls in plan.repls.items():
        text = cfg.texts[path]
        for ls, le, repl in sorted(repls, reverse=True):
            text = text[:ls] + repl + text[le:]
        plan.edits[path] = text
    if not ours:
        if not moving and not state:
            raise Fail(f'no nginx server listens on port {port}')
        text = plan.edits.get(cfg.main, cfg.texts[cfg.main])
        if plan.load_module:
            text = f'load_module {plan.load_module}; {ADDED}\n' + text
            plan.notes.setdefault(cfg.main, []).append(f'first line: load_module {plan.load_module}')
        text = text + ('' if text.endswith('\n') or not text else '\n') + (
            f'include {STREAM_CONF}; {ADDED} port {port} is shared by SNI: new HTTPS sites listen on '
            f'127.0.0.1:{site_port} ssl{" proxy_protocol" if pp else ""} instead (see: sx-nginx-sni status)\n')
        plan.edits[cfg.main] = text
        plan.notes.setdefault(cfg.main, []).append(f'last line: include {STREAM_CONF}')
    elif plan.load_module:
        raise Fail('the stream module is not loaded although the routing is set up; check the nginx configuration')
    return plan, site_port, listen_specs, pp


# ---------- commands ----------
def build_state(a, ngx, state, site_port, listen_specs, pp, route):
    st = dict(state) if state else {'version': 1, 'port': a.port, 'routes': [], 'edited_files': []}
    st.update(nginx_bin=ngx.bin, nginx_conf=ngx.conf, nginx_unit=ngx.unit, site_port=site_port,
              listen=listen_specs, proxy_protocol=pp)
    same = lambda r: r['domain'] == route['domain'] or r['owner'] == route['owner']  # one route per owner
    routes = [r for r in st['routes'] if not same(r)]
    old = next((r for r in st['routes'] if same(r)), None)
    hop = old['hop'] if old else None
    if pp and not hop:
        taken = {site_port} | {r['hop'] for r in routes if r.get('hop')}
        hop = pick_port(site_port + 1, taken)
    routes.append(dict(route, hop=hop))
    st['routes'] = sorted(routes, key=lambda r: r['domain'])
    return st


def show_plan(cfg, plan, st, ngx):
    edited = list(plan.edits)
    print()
    print(f'nginx ({ngx.conf}) loads {len(cfg.order)} configuration file(s). Sharing port {st["port"]} needs a '
          f'change in {len(edited)} of them; every other file stays as it is:')
    for p in edited:
        for n in plan.notes.get(p, []):
            print(f'  {p}: {n}')
    print(f'New file {STREAM_CONF} (the SNI routing):')
    print(''.join('    ' + ln + '\n' for ln in stream_conf(st).splitlines()), end='')
    if st['proxy_protocol']:
        print('The moved websites keep seeing visitor addresses (PROXY protocol + real_ip_header).')
    else:
        warn('this nginx has no realip module, so the websites will see 127.0.0.1 as the visitor address')
    print(f'Inside the moved servers $server_port becomes {st["site_port"]} (e.g. FastCGI SERVER_PORT); '
          'apps that build URLs from it can use $proxy_protocol_server_port.')
    for w in plan.warnings:
        warn(w)
    print(f'Backups go to {STATE_DIR}/backup/. nginx is reloaded, not restarted.')


def confirm_each(cfg, plan):
    for p, new in plan.edits.items():
        print()
        diff = difflib.unified_diff(cfg.texts[p].splitlines(), new.splitlines(), p, p + ' (new)', lineterm='', n=1)
        print('\n'.join(diff))
        if not ask(f'Change {p}?'):
            print(f'Nothing was changed (declined {p}).')
            return False
    return True


def probe_addr(specs):
    return '127.0.0.1' if any(spec_host(x) == '*' for x in specs) else '[::1]'


def apply_changes(ngx, cfg, plan, st, state_before):
    """Back up, write, test, reload, verify; on any failure or interruption put everything back."""
    ts = time.strftime('%Y%m%d-%H%M%S')
    os.makedirs(STATE_DIR, mode=0o755, exist_ok=True)
    saved = {p: cfg.texts[p] for p in plan.edits}
    try:
        with open(STREAM_CONF, encoding='utf-8') as f:
            saved_stream = f.read()
    except FileNotFoundError:
        saved_stream = None
    for p in plan.edits:
        dst = os.path.join(STATE_DIR, 'backup', ts, p.lstrip('/'))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(p, dst)
    addr = probe_addr(st['listen'])
    before = probe(plan.sites, st['port'], addr) if plan.edits else {}
    st = dict(st, edited_files=sorted(set(st.get('edited_files', [])) | set(plan.edits)))
    # A dropped SSH session or Ctrl-C must not leave half-edited files behind.
    handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)}
    try:
        try:
            save_state(st)  # written first: if this process dies anyway, `remove` still finds the edited files
            write_atomic(STREAM_CONF, stream_conf(st))
            for p, new in plan.edits.items():
                write_atomic(p, new, like=p)
            rc, out = ngx.test()
            if rc != 0:
                raise Fail(f'nginx -t rejected the new configuration:\n{out.strip()}')
            ngx.reload()
            wait = [st['site_port']] if plan.edits else []
            if st['proxy_protocol']:
                wait += [r['hop'] for r in st['routes']]
            deadline = time.time() + 10
            while any(not port_open(p) for p in wait) and time.time() < deadline:
                time.sleep(0.5)
            missing = [p for p in wait if not port_open(p)]
            if missing:
                raise Fail(f'nginx did not start listening on 127.0.0.1:{missing} after the reload')
            after = probe(plan.sites, st['port'], addr) if plan.edits else {}
            broken = [n for n, c in before.items() if c != '000' and after.get(n, '000') == '000']
            if broken:
                raise Fail(f'these websites stopped answering on port {st["port"]}: {", ".join(broken)}')
            for n, c in before.items():
                if after.get(n) != c:
                    warn(f'https://{n}/ answered {c} before and {after.get(n)} after the change')
        except BaseException as e:
            for p, text in saved.items():
                write_atomic(p, text, like=p)
            if saved_stream is None:
                try:
                    os.remove(STREAM_CONF)
                except FileNotFoundError:
                    pass
            else:
                write_atomic(STREAM_CONF, saved_stream)
            if state_before:
                save_state(state_before)
            else:
                try:
                    os.remove(STATE_FILE)
                except FileNotFoundError:
                    pass
            if ngx.test()[0] == 0:
                try:
                    ngx.reload()
                except Fail as e2:
                    warn(f'reloading the restored configuration: {e2}')
            raise Fail(f'{e or type(e).__name__}\nAll nginx files were restored and nginx was reloaded with them.')
    finally:
        for sig, h in handlers.items():
            signal.signal(sig, h)


def route_args(a):
    dom = a.domain.lower().rstrip('.')
    if not DOMAIN_RE.match(dom):
        raise Fail(f'invalid domain: {a.domain}')
    m = re.fullmatch(r'127\.0\.0\.1:(\d+)', a.backend or '')
    if not m or not 0 < int(m.group(1)) < 65536:
        raise Fail('--backend must be 127.0.0.1:PORT')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', a.owner or ''):
        raise Fail('--owner must be a simple name')
    return {'domain': dom, 'backend': a.backend, 'owner': a.owner}


def cmd_add(a, dry_run):
    route = route_args(a)
    state = load_state()
    if state and state['port'] != a.port:
        raise Fail(f'port {state["port"]} is already shared; one shared port is supported')
    if state:
        other = next((r for r in state['routes'] if r['domain'] == route['domain'] and r['owner'] != route['owner']), None)
        if other:
            raise Fail(f'{route["domain"]} is already routed to {other["owner"]}')
    ngx = Nginx(a, state)
    rc, out = ngx.test()
    if rc != 0:
        raise Fail(f'the current nginx configuration does not pass nginx -t; fix it first:\n{out.strip()}')
    cfg = Config(ngx.conf)
    plan, site_port, specs, pp = make_plan(cfg, ngx, state, a.port, route)
    st = build_state(a, ngx, state, site_port, specs, pp, route)
    try:
        with open(STREAM_CONF, encoding='utf-8') as f:
            current = f.read()
    except FileNotFoundError:
        current = None
    if not plan.edits and current == stream_conf(st) and state == st:
        info(f'{route["domain"]} already goes to {route["backend"]} through port {a.port}; nothing to change')
        return 0
    if plan.edits:
        show_plan(cfg, plan, st, ngx)
        if dry_run:
            for p, new in plan.edits.items():
                print()
                print('\n'.join(difflib.unified_diff(cfg.texts[p].splitlines(), new.splitlines(), p, p + ' (new)', lineterm='', n=1)))
            return 0
        if not sys.stdin.isatty():
            raise Fail('changing existing nginx files needs your confirmation for each file: run this in a terminal')
        if not confirm_each(cfg, plan):
            return 3
    elif dry_run:
        print(stream_conf(st), end='')
        return 0
    apply_changes(ngx, cfg, plan, st, state)
    info(f'port {a.port}: {route["domain"]} -> {route["backend"]}; other names -> nginx websites (127.0.0.1:{site_port})')
    return 0


def revert_text(text):
    out = []
    for line in text.splitlines(keepends=True):
        if ADDED in line:
            continue
        i = line.find(ORIG)
        if i >= 0:
            indent = line[:len(line) - len(line.lstrip())]
            nl = '\n' if line.endswith('\n') else ''
            line = indent + line[i + len(ORIG):].rstrip('\n') + nl
        out.append(line)
    return ''.join(out)


def cmd_remove(a):
    state = load_state()
    if not state:
        info('port sharing is not set up; nothing to remove')
        return 0
    keep = [r for r in state['routes'] if not (r['owner'] == a.owner and (not a.domain or r['domain'] == a.domain.lower()))]
    if keep == state['routes']:
        info(f'no route for {a.owner}; nothing to remove')
        return 0
    ngx = Nginx(a, state)
    if keep:
        st = dict(state, routes=keep)
        cfg = Config(ngx.conf)
        apply_changes(ngx, cfg, Plan(), st, state)
        info(f'removed the routes of {a.owner}; still shared with: {", ".join(r["owner"] for r in keep)}')
        return 0
    # Last route: put nginx back as it was (only the marked lines change).
    edits = {}
    for p in state['edited_files']:
        try:
            with open(p, encoding='utf-8', newline='') as f:
                text = f.read()
        except FileNotFoundError:
            warn(f'{p} no longer exists'); continue
        new = revert_text(text)
        if new != text:
            edits[p] = (text, new)
    try:
        with open(STREAM_CONF, encoding='utf-8') as f:
            stream_text = f.read()
    except FileNotFoundError:
        stream_text = None
    handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)}
    try:
        for p, (_, new) in edits.items():
            write_atomic(p, new, like=p)
        if stream_text is not None:
            os.remove(STREAM_CONF)
        rc, out = ngx.test()
        if rc != 0:
            for p, (old, _) in edits.items():
                write_atomic(p, old, like=p)
            if stream_text is not None:
                write_atomic(STREAM_CONF, stream_text)
            raise Fail(f'nginx -t rejected the restored configuration, so nothing was changed:\n{out.strip()}')
        os.remove(STATE_FILE)  # the files now match a configuration without sharing
    finally:
        for sig, h in handlers.items():
            signal.signal(sig, h)
    for p in edits:
        info(f'restored the lines this tool had changed in {p}')
    try:
        ngx.reload()
    except Fail as e:
        raise Fail(f'the files are restored, but {e}; reload nginx yourself (e.g. systemctl reload nginx)')
    info(f'port {state["port"]} belongs to nginx again (backups stay in {STATE_DIR}/backup/)')
    return 0


def cmd_status(a):
    state = load_state()
    if not state:
        print('port sharing is not set up')
        return 0
    print(f'port {state["port"]} is shared by SNI ({STREAM_CONF}); nginx websites at 127.0.0.1:{state["site_port"]}')
    for r in state['routes']:
        print(f'  {r["domain"]} -> {r["backend"]} ({r["owner"]})')
    print('edited files: ' + ', '.join(state['edited_files']))
    # A site added later with `listen 443 ssl` (by hand or by certbot --nginx) passes nginx -t, but the reload
    # cannot bind the port and the next nginx restart fails: point those out.
    try:
        cfg = Config(state['nginx_conf'])
    except Fail as e:
        warn(f'could not read the nginx configuration: {e}')
        return 1
    clash = [d for d in cfg.walk() if d.name == 'listen' and d.args and d.ctx == ['http', 'server']
             and (split_listen(d.args[0]) or (None, None))[1] == state['port']
             and not any(x in ('quic', 'http3') for x in d.args[1:])]
    for d in clash:
        warn(f'{d.file}:{d.line} listens on port {state["port"]} itself, which clashes with the SNI routing '
             f'(nginx will fail to restart). Run the deploy script again (or nginx_sni.py add) to move it to '
             f'127.0.0.1:{state["site_port"]}')
    return 1 if clash else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('command', choices=('status', 'plan', 'add', 'remove'))
    ap.add_argument('--domain')
    ap.add_argument('--backend')
    ap.add_argument('--owner')
    ap.add_argument('--port', type=int, default=443)
    ap.add_argument('--nginx-bin')
    ap.add_argument('--nginx-conf')
    a = ap.parse_args()
    try:
        if a.command == 'status':
            return cmd_status(a)
        if os.geteuid() != 0 and not os.environ.get('SX_SNI_DIR'):
            raise Fail('run as root')
        if a.command in ('plan', 'add'):
            if not (a.domain and a.backend and a.owner):
                raise Fail(f'{a.command} needs --domain, --backend and --owner')
            return cmd_add(a, dry_run=a.command == 'plan')
        if not a.owner:
            raise Fail('remove needs --owner')
        return cmd_remove(a)
    except Fail as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
