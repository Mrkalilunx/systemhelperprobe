#!/usr/bin/env python3
"""
穷举恢复 SystemHelper 上报报文的明文

原理
密钥 = MD5(明文)，明文模板硬编码在 APK 里，只有少数字段有熵
逐个猜测候选明文、算 MD5、解 AES，解出合法 JSON 即命中

用法
    python3 bruteplaintext.py body.b64 template.json --tac 86493605 --time "2026-11-11 02:08:18"
    python3 bruteplaintext.py body.b64 template.json --tac 86493605 --time "2026-11-11 02:08:18" --spread 5

    body.b64      base64 的密文，一行
    template.json 明文模板，待猜字段写成 <I1> <I2>，时间写成 <TIME> 或直接写死
    --tac         IMEI 前 8 位，可按机型反查
    --time        抓包时间戳，精确到秒
    --spread      时间允许的秒级浮动，默认 0 表示只试给定那一秒

依赖
    pip install pycryptodome
"""

import sys
import time
import hashlib
import base64
import argparse
import datetime
from Crypto.Cipher import AES

# 同批次 IMEI 常连号，实测序列号差值为 1
IMEIOFFSET = 1


def trydecode(body, plain):
    """用候选明文派生密钥解 body，命中返回 (key, 明文)"""
    key = hashlib.md5(plain.encode()).digest()
    raw = AES.new(key, AES.MODE_ECB).decrypt(body)
    last = raw[-1]
    if 1 <= last <= 16 and raw.endswith(bytes([last]) * last):
        raw = raw[:-last]
    # 命中判据只用格式，不需要事先知道任何字段值
    if raw.startswith(b'{"') and raw.endswith(b"}"):
        try:
            return key, raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return None


def luhncheck(s14):
    """按 Luhn 算法算出 IMEI 第 15 位校验位

    IMEI 是 TAC 8 位 + 序列 6 位 + 校验 1 位
    校验位由前 14 位唯一确定，不占熵，所以搜索空间是 10^6 而不是 10^7
    """
    total = 0
    for i, ch in enumerate(s14):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def buildimei(tac, serial):
    """由 TAC 与 6 位序列号拼出完整 15 位 IMEI"""
    s14 = f"{tac}{serial:06d}"
    return s14 + luhncheck(s14)


def shifts(spread, base):
    """按秒级浮动生成时间候选，先试中心"""
    order = [0]
    for d in range(1, spread + 1):
        order += [-d, d]
    for d in order:
        yield (base + datetime.timedelta(seconds=d)).strftime("%Y-%m-%d %H:%M:%S")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("body")
    ap.add_argument("template")
    ap.add_argument("--tac", default="00000000", help="IMEI 前 8 位")
    ap.add_argument("--time", dest="tstr", required=True, help="抓包时间 yyyy-MM-dd HH:mm:ss")
    ap.add_argument("--spread", type=int, default=0, help="时间秒级浮动范围")
    ap.add_argument("--tries", type=int, default=1_000_000, help="IMEI 序列号的枚举上限，6 位即 10^6")
    a = ap.parse_args()

    body = base64.b64decode(open(a.body).read().strip())
    tmpl = open(a.template, encoding="utf-8").read()
    base = datetime.datetime.strptime(a.tstr, "%Y-%m-%d %H:%M:%S")
    times = list(shifts(a.spread, base))
    print(f"密文 {len(body)} 字节  时间候选 {len(times)} 个  枚举上限 {a.tries:,}")

    t0 = time.time()
    tries = 0
    for ts in times:
        tpl = tmpl.replace("<TIME>", ts)
        for serial in range(a.tries):
            i1 = buildimei(a.tac, serial)
            i2 = buildimei(a.tac, serial + IMEIOFFSET)
            cand = tpl.replace("<I1>", i1).replace("<I2>", i2)
            tries += 1
            r = trydecode(body, cand)
            if r:
                dt = time.time() - t0
                print(f"\n命中  尝试 {tries:,} 次  耗时 {dt:.2f}s  {tries / dt:,.0f}/s")
                print(f"时间 {ts}")
                print(f"IMEI1 {i1}   IMEI2 {i2}")
                print(f"密钥 {r[0].hex()}")
                print("明文 " + r[1])
                return 0
            if tries % 50000 == 0:
                dt = time.time() - t0
                print(f"  {tries:,} 次  {tries / dt:,.0f}/s", end="\r", flush=True)
    print(f"\n未命中，已试 {tries:,} 次")
    return 1


if __name__ == "__main__":
    sys.exit(main())
