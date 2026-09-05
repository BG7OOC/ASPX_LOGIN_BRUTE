# AspxBrute - ASPX 登录口口令测试工具

> Author: **BG7OOC**

专为 ASP.NET WebForms 登录表单设计的口令测试工具，自动处理 `__VIEWSTATE` / `__EVENTVALIDATION` / `__VIEWSTATEGENERATOR` 等隐藏字段，专治"普通爆破工具一打 ASPX 就废"的痛点。

> ⚠️ **仅供授权测试 / 学习使用**。未经授权对他人系统进行口令测试属违法行为，使用者自行承担法律责任。

## 为什么需要它

ASP.NET WebForms 登录页有特殊机制，普通 HTTP 爆破工具（Hydra 等）经常失效：

1. **`__VIEWSTATE` / `__EVENTVALIDATION`** — 每次 POST 必须回带，否则报错
2. **字段名不固定** — `Login1_UserName`、`txtUser`、`txtPass`、`btnLogin` 五花八门
3. **登录成功判定难** — 有的是 302 跳转 /default.aspx，有的返回错误页

AspxBrute 自动处理以上三点。

## 功能特性

- **自动提取隐藏字段**：`__VIEWSTATE`、`__EVENTVALIDATION`、`__VIEWSTATEGENERATOR`
- **自动识别表单字段**：用户名、密码、登录按钮（支持常见命名风格）
- **多结果判定**：成功关键字 / 302 跳转 / 失败关键字 / 长度启发式
- **锁定防护检测**：发现"锁定/验证码"关键字自动停止，避免打挂目标
- **多线程 + 慢速模式**：平衡速度与隐蔽性
- **代理支持**：方便接入 Burp Suite 观察流量
- **UA 轮换**：降低被特征拦截概率

## 安装

```bash
pip install requests
```

## 使用方法

### 基础用法（单用户爆破）

```bash
python aspx_bruteforce.py -u http://target/login.aspx -U admin -W wordlists/passwords.txt
```

### 多用户（用户名列表 × 密码字典）

```bash
python aspx_bruteforce.py -u http://target/login.aspx -U wordlists/users.txt --userlist -W wordlists/passwords.txt
```

### 小心试探（慢速 + 代理）— 推荐实际测试用

```bash
python aspx_bruteforce.py -u http://target/login.aspx -U admin -W pass.txt -t 3 --delay 1 --proxy http://127.0.0.1:8080
```

### 自定义判定

```bash
# 明确成功/失败关键字（中文站很常见）
python aspx_bruteforce.py -u http://target/Login.aspx -U admin -W pass.txt \
    --success-keyword "欢迎您" --fail-keyword "用户名或密码错误"

# 认为 302 跳转即成功
python aspx_bruteforce.py -u http://target/Login.aspx -U admin -W pass.txt --success-redirect

# 检测到锁定立即停止
python aspx_bruteforce.py -u http://target/Login.aspx -U admin -W pass.txt --lock-keyword "锁定,验证码,Locked"
```

### 账号密码配对模式

```bash
# pair.txt 每行格式: user:pass
python aspx_bruteforce.py -u http://target/Login.aspx -W pair.txt --pair
```

### 手动指定字段名（自动识别失败时）

```bash
python aspx_bruteforce.py -u http://target/Login.aspx -U admin -W pass.txt \
    --user-field Login1_UserName --pass-field Login1_Password --button-field Login1_LoginButton
```

## 参数说明

| 参数 | 必填 | 说明 |
|------|------|------|
| `-u` / `--url` | 是 | 登录页 URL |
| `-U` / `--user` | 是* | 用户名或用户名列表文件（`--pair` 时不需要） |
| `--userlist` | 否 | `-U` 为用户名列表文件 |
| `-W` / `--wordlist` | 是 | 密码字典文件 |
| `--pair` | 否 | 配对模式，字典每行 `user:pass` |
| `-t` / `--threads` | 否 | 并发数，默认 5 |
| `--delay` | 否 | 每次请求间隔（秒），默认 0 |
| `--timeout` | 否 | 请求超时，默认 10s |
| `--proxy` | 否 | HTTP 代理（可接 Burp） |
| `--success-keyword` | 否 | 成功页特征关键字 |
| `--success-redirect` | 否 | 302 离开登录页视为成功 |
| `--fail-keyword` | 否 | 失败页特征关键字 |
| `--lock-keyword` | 否 | 锁定/验证码提示（逗号分隔），命中即停 |
| `--user-field` | 否 | 强制用户名 field |
| `--pass-field` | 否 | 强制密码 field |
| `--button-field` | 否 | 强制按钮 field |
| `--ssl-verify` | 否 | 校验证书（默认忽略） |

## 判定逻辑（默认启发式）

无自定义参数时按以下顺序判定成功：
1. 已检测到锁定 → 一律算失败并停止
2. 命中 `--success-keyword` → 成功
3. `--success-redirect` 且发生 302 → 成功
4. 指定了 `--fail-keyword` → 响应不含该关键字算成功
5. **302 跳转离开登录页** → 成功
6. 响应长度相对基线变化 **>40%** → 命中（响应异常变化，供人工复核）

## 工作原理

```
获取登录页 GET /login.aspx
    ↓ 正则提取 <input> 字段
    ↓ 自动识别 user/pass/button 字段名
    ↓ 提取 __VIEWSTATE / __EVENTVALIDATION
基线探测：用不存在账号发一次，记录失败响应特征
    ↓ 多线程，每个请求带上隐藏字段 + 账号密码
    ↓ POST 提交
判定：关键字 / 302 / 长度启发 → 锁定停止
    ↓
输出有效口令
```

## 测试环境自测

本目录 `wordlists/` 为示例字典。可用本地 Python 模拟 ASPX 登录页自测：

```python
# 简易模拟服务器（见 tests/ 思路），字段名 Login1_UserName / Login1_Password
# 有效账号: admin/pass123, test/123456, bob/letmein
```

实测结果（本地模拟）：
- 单用户爆破：`admin : pass123` ✅
- 多用户爆破：3/5 用户命中 ✅
- 锁定检测：连续错 3 次触发，工具自动停止 ✅

## 目录结构

```
ASPX_LOGIN_BRUTE/
├── aspx_bruteforce.py      # 主工具
├── wordlists/
│   ├── passwords.txt        # 示例密码字典
│   └── users.txt            # 示例用户名列表
└── README.md
```

## 免责声明

本项目仅用于**授权环境下的安全测试与学习**，包括但不限于：自有系统、甲方授权的渗透测试、CTF 靶场、企业/学校的授权安全演练。任何未经授权使用造成的后果由使用者自行承担，作者不承担任何责任。

## License

MIT License - BG7OOC