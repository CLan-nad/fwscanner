#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
import sys
import fnmatch
import html  # 用于HTML转义
from collections import defaultdict

# ---------------------- 配置与工具函数 ----------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(CURRENT_DIR, "data")
HEAVY_THRESHOLD = 50  # 大量命中的阈值

IPV4_RE = re.compile(r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
URL_RE = re.compile(r"https?://[^/\"']+")
EMAIL_RE = re.compile(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+\.[A-Za-z.]{2,6}")
MD5CRYPT_RE = re.compile(r"\$1\$\w{8}\S{23}")


def load_list(name):
    """读取 data/ 下的规则文件，忽略空行和 # 注释。"""
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        return []
    out = []
    try:
        with open(path, 'r') as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                out.append(s)
    except Exception:
        pass
    return out


def iter_files(root, excludes):
    """递归遍历 root，跳过名字在 excludes 集合内的目录。"""
    exset = set(excludes)
    for dirpath, dirnames, filenames in os.walk(root):
        # 过滤排除目录
        dirnames[:] = [d for d in dirnames if d not in exset]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def match_globs(name, globs):
    return any(fnmatch.fnmatch(name, g) for g in globs)


def relpath(p, root):
    try:
        return os.path.relpath(p, root)
    except Exception:
        return p

# ---------------------- 各类扫描 ----------------------

def scan_named_files(root, patterns, excludes):
    res = dict((p, []) for p in patterns)
    for p in patterns:
        for f in iter_files(root, excludes):
            if match_globs(os.path.basename(f), [p]):
                res[p].append(relpath(f, root))
    return res


def scan_shell_scripts(root, excludes):
    """仅收集启动相关的脚本，如 etc/init.d、rcS、rc.local、rc.d 等。"""
    hits = []
    keywords = ["init.d", "rc.d"]
    special_files = ["rcS", "rc.local"]
    
    for f in iter_files(root, excludes):
        rp = relpath(f, root)
        filename = os.path.basename(f)
        _, ext = os.path.splitext(f)
        
        if ext == ".sh":
            # 仅限路径中包含 init.d / rc.d，或文件名为 rcS/rc.local
            if any(k in rp for k in keywords) or filename in special_files:
                hits.append(rp)
        else:
            # 某些系统启动脚本可能没有 .sh 后缀（如 rcS/rc.local）
            if filename in special_files:
                hits.append(rp)
    return sorted(set(hits))


def scan_bin_files(root, excludes):
    hits = []
    for f in iter_files(root, excludes):
        if f.endswith('.bin'):
            hits.append(relpath(f, root))
    return hits


def scan_text_patterns(root, patterns, excludes):
    res = dict((p, []) for p in patterns)
    for f in iter_files(root, excludes):
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as file_obj:
                data = file_obj.read()
        except Exception:
            continue
        
        for p in patterns:
            if re.search(r"(?i)\b" + re.escape(p) + r"\b", data):
                res[p].append(relpath(f, root))
    return res


def scan_regex_values(root, rx, excludes):
    hits = set()
    for f in iter_files(root, excludes):
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as file_obj:
                data = file_obj.read()
        except Exception:
            continue
        
        for m in rx.findall(data):
            if isinstance(m, tuple):
                s = ".".join(m)
            else:
                s = m
            hits.add(s)
    return sorted(hits)


def _iter_text_files(root, excludes):
    """遍历可能的文本配置/脚本文件，返回 (path, relpath)。"""
    text_exts = [".conf", ".cfg", ".ini", ".cnf", ".properties",
                ".xml", ".json", ".yaml", ".yml", ".txt", ".log",
                ".sh", ".service", ".network", ".rules", ".link", ".socket",
                ".pem", ".crt", ".cer", ".key", ".pub"]
    prefer_dirs = ["etc", "config", "configs", "network", "net", "init.d", "rc.d"]
    
    for f in iter_files(root, excludes):
        rp = relpath(f, root)
        dirname = os.path.dirname(rp)
        _, ext = os.path.splitext(f)
        
        if ext.lower() in text_exts or any(d in dirname for d in prefer_dirs):
            yield f, rp


def count_pattern_by_file(root, rx, excludes, post=None):
    """统计每个文件中正则命中次数。"""
    counts = {}
    for f, rp in _iter_text_files(root, excludes):
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as file_obj:
                data = file_obj.read()
        except Exception:
            continue
        
        found = rx.findall(data)
        c = 0
        for m in found:
            s = ".".join(m) if isinstance(m, tuple) else m
            if post:
                s = post(s)
                if s is None:
                    continue
            c += 1
        if c > 0:
            counts[rp] = c
    return counts


def filter_heavy_hits(counts, threshold=HEAVY_THRESHOLD):
    """筛选高命中文件，并按次数降序。"""
    items = [(p, n) for p, n in counts.items() if n >= threshold]
    return sorted(items, key=lambda x: (-x[1], x[0]))


def post_global_ipv4(val):
    """仅保留全局可路由 IPv4，其他返回 None 以便过滤。"""
    try:
        import ipaddress
        addr = ipaddress.ip_address(val)
        if addr.version == 4 and addr.is_global:
            return str(addr)
    except Exception:
        return None
    return None


def scan_ip_addresses(root, excludes):
    """更高质量地提取 IP。"""
    import ipaddress

    text_exts = [".conf", ".cfg", ".ini", ".cnf", ".properties",
                ".xml", ".json", ".yaml", ".yml", ".txt", ".sh", ".service", ".network",
                ".hosts", ".iface", ".rules", ".link", ".socket"]
    prefer_dirs = ["etc", "config", "configs", "network", "net", "init.d", "rc.d"]

    hits = set()
    for f in iter_files(root, excludes):
        rp = relpath(f, root)
        dirname = os.path.dirname(rp)
        _, ext = os.path.splitext(f)
        
        if ext.lower() not in text_exts and not any(d in dirname for d in prefer_dirs):
            continue
        
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as file_obj:
                data = file_obj.read()
        except Exception:
            continue
        
        for s in IPV4_RE.findall(data):
            if isinstance(s, tuple):
                s = ".".join(s)
            try:
                addr = ipaddress.ip_address(s)
                if addr.version == 4 and addr.is_global:
                    hits.add(str(addr))
            except Exception:
                continue
    return sorted(hits)


def scan_private_keys(root, excludes):
    """检测包含私钥块的文件。"""
    key_markers = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ]
    hits = set()
    for f, rp in _iter_text_files(root, excludes):
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as file_obj:
                data = file_obj.read()
        except Exception:
            continue
        
        if any(m in data for m in key_markers):
            hits.add(rp)
    return sorted(hits)


def scan_api_secrets_by_file(root, excludes):
    """检测可能的 API Key/Token/Secret 的高命中文件。"""
    token_re = re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|bearer\s+[A-Za-z0-9\-_.=:+/]{10,})")
    counts = count_pattern_by_file(root, token_re, excludes)
    return filter_heavy_hits(counts)


def scan_phone_numbers_by_file(root, excludes):
    """检测大量电话号码的文件。"""
    phone_re = re.compile(r"\b1[3-9]\d{9}\b")
    counts = count_pattern_by_file(root, phone_re, excludes)
    return filter_heavy_hits(counts)


def scan_crypto_indicators_by_file(root, excludes):
    """检测加解密/签名/校验相关关键词的高命中文件。"""
    crypto_re = re.compile(r"(?i)\b(aes|rsa|openssl|des|decrypt|encrypt|signature|verify|checksum|sha1|sha256|md5|certificate|keystore)\b")
    counts = count_pattern_by_file(root, crypto_re, excludes)
    return filter_heavy_hits(counts, threshold=5)

# ---------------------- 主流程与输出 ----------------------

def run_scan(root, excludes, no_ssl=False):
    passfiles = load_list("passfiles")
    sslfiles = load_list("sslfiles")
    sshfiles = load_list("sshfiles")
    files = load_list("files")
    dbfiles = load_list("dbfiles")
    patterns = load_list("patterns")
    webservers = load_list("webservers")
    binaries = load_list("binaries")

    payload = {}
    payload["password_files"] = scan_named_files(root, passfiles, excludes)
    payload["unix_md5_hashes"] = scan_regex_values(root, MD5CRYPT_RE, excludes)
    payload["ssl_files"] = scan_named_files(root, sslfiles, excludes)
    payload["ssh_files"] = scan_named_files(root, sshfiles, excludes)
    payload["files"] = scan_named_files(root, files, excludes)
    payload["db_files"] = scan_named_files(root, dbfiles, excludes)
    payload["shell_scripts"] = scan_shell_scripts(root, excludes)
    payload["bin_files"] = scan_bin_files(root, excludes)
    payload["text_patterns"] = scan_text_patterns(root, patterns, excludes)
    payload["webservers"] = scan_named_files(root, webservers, excludes)
    payload["binaries"] = scan_named_files(root, binaries, excludes)
    
    # 高命中文件统计
    email_counts = count_pattern_by_file(root, EMAIL_RE, excludes)
    url_counts = count_pattern_by_file(root, URL_RE, excludes)
    ip_counts = count_pattern_by_file(root, IPV4_RE, excludes, post=post_global_ipv4)
    
    payload["heavy_emails"] = filter_heavy_hits(email_counts)
    payload["heavy_urls"] = filter_heavy_hits(url_counts)
    payload["heavy_ips"] = filter_heavy_hits(ip_counts)
    
    # 新增关键敏感项
    payload["private_keys"] = scan_private_keys(root, excludes)
    payload["secret_rich_files"] = scan_api_secrets_by_file(root, excludes)
    payload["phone_rich_files"] = scan_phone_numbers_by_file(root, excludes)
    payload["crypto_rich_files"] = scan_crypto_indicators_by_file(root, excludes)
    
    return payload


def write_html(path, payload):
    """生成HTML报告"""
    def flat(d):
        res = []
        for v in d.values():
            res.extend(v)
        return res

    def format_counts(items):
        return ["%s : %s" % (p, n) for p, n in (items or [])]

    html_parts = [
        "<!doctype html>",
        "<html lang=\"zh-CN\">",
        "<head>",
        "  <meta charset=\"utf-8\">",
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "  <title>固件扫描报告</title>",
        "  <style>",
        "    :root{--bg:#0b1020;--panel:#111a2b;--text:#e6edf3;--muted:#9aa4b2;--accent:#3da9fc;--ok:#2ea043;--warn:#d29922;--danger:#f85149;}",
        "    body{background:var(--bg);color:var(--text);font:14px/1.6 system-ui,Segoe UI,Roboto,Helvetica,Arial; margin:0;padding:24px;}",
        "    h1{font-size:22px;margin:0 0 12px;} h2{font-size:18px;margin:20px 0 8px;}",
        "    .meta{color:var(--muted);margin-bottom:12px;}",
        "    section{background:var(--panel);padding:12px 12px 4px;border-radius:8px;margin:12px 0;}",
        "    table{width:100%;border-collapse:collapse;} thead th{color:var(--muted);font-weight:600;text-align:left;border-bottom:1px solid #223;}",
        "    td,th{padding:6px 8px;vertical-align:top;} tr:nth-child(even){background:#0e1525;}",
    ]

    html_parts = [
        "<!doctype html>",
        "<html lang=\"zh-CN\">",
        "<head>",
        "  <meta charset=\"utf-8\">",
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "  <title>固件扫描报告</title>",
        "  <style>",
        "    :root{--bg:#0b1020;--panel:#111a2b;--text:#e6edf3;--muted:#9aa4b2;--accent:#3da9fc;--ok:#2ea043;--warn:#d29922;--danger:#f85149;}",
        "    body{background:var(--bg);color:var(--text);font:14px/1.6 system-ui,Segoe UI,Roboto,Helvetica,Arial; margin:0;padding:24px;}",
        "    h1{font-size:22px;margin:0 0 12px;} h2{font-size:18px;margin:20px 0 8px;}",
        "    .meta{color:var(--muted);margin-bottom:12px;}",
        "    section{background:var(--panel);padding:12px 12px 4px;border-radius:8px;margin:12px 0;}",
        "    table{width:100%;border-collapse:collapse;} thead th{color:var(--muted);font-weight:600;text-align:left;border-bottom:1px solid #223;}",
        "    td,th{padding:6px 8px;vertical-align:top;} tr:nth-child(even){background:#0e1525;}",
        "    .muted{color:var(--muted);}",
        "    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;}",
        "  </style>",
        "</head>",
        "<body>",
        "  <h1>固件扫描报告</h1>",
        "  <div class=\"meta\">由 fwscanner 生成</div>",
    ]

    html_parts.append("<div class=\"grid\">")

    def add_section(title, items):
        if not items:
            rows = '<tr><td class="muted" colspan="2">无</td></tr>'
        else:
            rows = "\n".join(
                "<tr><td>%s</td><td>%s</td></tr>" % (i+1, html.escape(str(it))) 
                for i, it in enumerate(items)
            )
        section_html = """
        <section>
            <h2>%s</h2>
            <table>
            <thead><tr><th>#</th><th>内容</th></tr></thead>
            <tbody>
                %s
            </tbody>
            </table>
        </section>
        """ % (html.escape(title), rows)
        html_parts.append(section_html)

    add_section("密码文件", flat(payload.get("password_files", {})))
    add_section("Unix MD5 哈希", payload.get("unix_md5_hashes", []))
    add_section("SSL 文件", flat(payload.get("ssl_files", {})))
    add_section("SSH 文件", flat(payload.get("ssh_files", {})))
    # 只统计自启动相关配置文件和shell脚本
    autostart_config_keywords = [
        "inittab", "rcS", "rc.local", "init.d", "rc.d", "system.conf",
        "network/interfaces", "hostapd.conf", "udhcpd.conf", "pppoe.conf"
    ]
    autostart_configs = [f for f in flat(payload.get("files", {})) if any(k in f for k in autostart_config_keywords)]
    autostart_shells = [f for f in payload.get("shell_scripts", []) if any(k in f for k in autostart_config_keywords)]
    merged_autostart = sorted(set(autostart_configs + autostart_shells))
    add_section("自启动相关配置文件与Shell脚本", merged_autostart)
    add_section("数据库文件", flat(payload.get("db_files", {})))
    add_section(".bin 文件", payload.get("bin_files", []))
    # 只显示命中次数多的关键模式（≥50）
    pattern_hits = [(k, len(v)) for k, v in payload.get("text_patterns", {}).items() if len(v) >= 50]
    add_section("高命中关键模式（模式:命中文件数≥50）", ["%s:%s" % (k, n) for k, n in pattern_hits])
    add_section("Web 服务器", flat(payload.get("webservers", {})))

    # 新增：高命中文件与敏感项
    add_section("高命中 IP 的文件", format_counts(payload.get("heavy_ips", [])))
    add_section("高命中 URL 的文件", format_counts(payload.get("heavy_urls", [])))
    add_section("高命中邮箱的文件", format_counts(payload.get("heavy_emails", [])))
    add_section("包含私钥的文件", payload.get("private_keys", []))
    add_section("疑似含有密钥/令牌的文件", format_counts(payload.get("secret_rich_files", [])))
    add_section("疑似包含大量电话号码的文件", format_counts(payload.get("phone_rich_files", [])))
    add_section("加解密/签名相关高命中文件", format_counts(payload.get("crypto_rich_files", [])))

    html_parts.append("</div>")
    html_parts.extend(["</body>", "</html>"])

    with open(path, 'w', encoding='utf-8') as f:
        f.write("\n".join(html_parts))

def main():
    parser = argparse.ArgumentParser(description="固件文件系统扫描器")
    parser.add_argument("firmdir", help="固件根目录（已解包的文件系统路径）")

    args = parser.parse_args()
    root = os.path.abspath(args.firmdir)
    if not os.path.exists(root) or not os.path.isdir(root):
        print("目录不存在或不可用: %s" % root)
        sys.exit(1)

    # 默认排除一些常见的虚拟或噪声目录
    excludes = ["dev", "proc", "sys", "tmp"]

    payload = run_scan(root, excludes=excludes, no_ssl=False)

    # 生成 HTML 报告
    out_path = os.path.join(os.getcwd(), "fwscanner_report.html")
    write_html(out_path, payload)
    print("报告已生成: %s" % out_path)

if __name__ == "__main__":
    main()