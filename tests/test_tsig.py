"""离线 TSIG（RFC 8945）校验测试（app.tsig 单元 + HTTP 端到端）。

报文用小型 wire 编码器现场签名，覆盖：

- authenticated（hmac-sha256/hmac-sha512、密钥名大小写、fudge 边界、
  响应前置 request_mac、压缩 owner/算法名、base64 密钥）；
- 依次否定 badkey / badalg / badsig / badtime（badtime 附 48 位时间）；
- 独立固定向量（按 RFC 8945 §5.2 由独立脚本生成后冻结，**不复用
  app.tsig 的任何拼装函数**）：普通请求、带 request_mac 的响应、
  hmac-sha256/hmac-sha512 双算法、单字节篡改 -> badsig；
- 结构错误 422：TSIG 缺失/重复/不在附加区末尾/错区、CLASS≠ANY、
  TTL≠0、Original ID 不符、各类截断、压缩指针越界/成环、尾随字节；
- 请求格式错误 400；成功轨迹不泄露共享密钥。
"""

import base64
import hmac
import json
import struct
import threading
import unittest
import urllib.error
import urllib.request

from app.review import ReviewError
from app.server import build_server
from app.tsig import verify_tsig

KEY_NAME = "tsig-key.example.com."
SECRET = b"s3cr3t-shared-key"
WHEN = 1700000000
FUDGE = 300
MID = 0x1234


# ---------------------------------------------------------------------------
# wire 构造与签名（与 RFC 8945 §5.2 同布局，独立于被测代码）
# ---------------------------------------------------------------------------

def wname(name: str) -> bytes:
    if name == ".":
        return b"\x00"
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.lower().encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def question(qname: str, qtype: int = 1, qclass: int = 1) -> bytes:
    return wname(qname) + struct.pack("!HH", qtype, qclass)


def query(mid: int = MID, qname: str = "www.example.com.",
          arcount: int = 1) -> bytes:
    return (
        struct.pack("!HHHHHH", mid, 0x0100, 1, 0, 0, arcount)
        + question(qname)
    )


def _variables(key_name, algorithm, when, fudge,
               error=0, other=b"") -> bytes:
    """RFC 8945 §5.2 第 3 项：规范 TSIG 变量（key_name/CLASS/TTL/算法/

    时间/fudge/error/other；Original ID 与 MAC Size 不属于 HMAC 输入）。
    """
    return (
        wname(key_name)
        + struct.pack("!HI", 255, 0)  # CLASS=ANY、TTL=0
        + wname(algorithm)
        + when.to_bytes(6, "big")
        + struct.pack("!H", fudge)
        + struct.pack("!HH", error, len(other))
        + other
    )


def sign(message: bytes, key_name: str = KEY_NAME, secret: bytes = SECRET,
         algorithm: str = "hmac-sha256.", when: int = WHEN,
         fudge: int = FUDGE, error: int = 0, other: bytes = b"",
         request_mac: bytes | None = None, arcount: int = 1):
    """在报文末尾追加一条规范 TSIG RR，返回 (带 TSIG 报文, MAC)。"""
    hash_name = "sha512" if "sha512" in algorithm else "sha256"

    pre = bytearray(message)
    struct.pack_into("!H", pre, 10, arcount - 1)
    data = b""
    if request_mac is not None:
        # 响应：request MAC 的 2 字节长度 + 内容位于最前
        data += struct.pack("!H", len(request_mac)) + request_mac
    data += bytes(pre)
    data += _variables(key_name, algorithm, when, fudge, error, other)
    mac = hmac.new(secret, data, hash_name).digest()

    rdata = (
        wname(algorithm)
        + when.to_bytes(6, "big")
        + struct.pack("!H", fudge)
        + struct.pack("!H", len(mac)) + mac
        + struct.pack("!HHH",
                      struct.unpack_from("!H", message, 0)[0],
                      error, len(other))
        + other
    )
    rr = (
        wname(key_name)
        + struct.pack("!HHIH", 250, 255, 0, len(rdata))
        + rdata
    )
    struct.pack_into("!H", pre, 10, arcount)
    return bytes(pre) + rr, mac


def a_record(name="www.example.com.", ip=(192, 0, 2, 80), ttl=60) -> bytes:
    return wname(name) + struct.pack("!HHIH", 1, 1, ttl, 4) + bytes(ip)


def response(answer: bytes = a_record(), mid: int = MID) -> bytes:
    return (
        struct.pack("!HHHHHH", mid, 0x8180, 1, 1, 0, 1)
        + question("www.example.com.") + answer
    )


def payload(message: bytes, **over) -> dict:
    p = {
        "message": base64.b64encode(message).decode(),
        "secret": SECRET.decode(),
        "key_name": KEY_NAME,
        "now": WHEN + 100,
    }
    p.update(over)
    return p


def expect422(testcase: unittest.TestCase, message: bytes, code: str,
              **over) -> None:
    with testcase.assertRaises(ReviewError) as ctx:
        verify_tsig(payload(message, **over))
    testcase.assertEqual(ctx.exception.status, 422)
    testcase.assertEqual(ctx.exception.code, code)


class TsigUnitTests(unittest.TestCase):
    def test_authenticated_sha256_and_trace(self):
        signed, _mac = sign(query())
        result = verify_tsig(payload(signed))
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["key_name"], KEY_NAME)
        self.assertEqual(result["algorithm"], "hmac-sha256.")
        self.assertEqual(result["mac_size"], 32)
        steps = [entry["step"] for entry in result["trace"]]
        self.assertEqual(
            steps,
            ["message", "tsig", "class_ttl", "original_id", "key",
             "algorithm", "mac", "time", "result"],
        )
        # 成功轨迹与结果绝不回显共享密钥/MAC 本体
        blob = json.dumps(result)
        self.assertNotIn(SECRET.decode(), blob)
        self.assertNotIn("717613", blob)

    def test_authenticated_sha512(self):
        signed, _ = sign(query(), algorithm="hmac-sha512.")
        result = verify_tsig(payload(signed))
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["algorithm"], "hmac-sha512.")
        self.assertEqual(result["mac_size"], 64)

    def test_key_name_case_insensitive_and_relative(self):
        signed, _ = sign(query())
        for given in ("TSIG-KEY.Example.COM", "tsig-key.example.com"):
            result = verify_tsig(payload(signed, key_name=given))
            self.assertEqual(result["status"], "authenticated", given)

    def test_fudge_boundaries(self):
        signed, _ = sign(query())
        self.assertEqual(
            verify_tsig(payload(signed, now=WHEN + FUDGE))["status"],
            "authenticated",
        )
        self.assertEqual(
            verify_tsig(payload(signed, now=WHEN - FUDGE))["status"],
            "authenticated",
        )
        result = verify_tsig(payload(signed, now=WHEN + FUDGE + 1))
        self.assertEqual(result["status"], "badtime")
        self.assertEqual(
            verify_tsig(payload(signed, now=WHEN - FUDGE - 1))["status"],
            "badtime",
        )

    def test_badtime_carries_48_bit_server_time(self):
        signed, _ = sign(query(), when=WHEN)
        now = WHEN + FUDGE + 1
        result = verify_tsig(payload(signed, now=now))
        self.assertEqual(result["status"], "badtime")
        self.assertEqual(result["server_time"], now)
        self.assertEqual(result["server_time_hex"], f"{now:012x}")
        self.assertEqual(len(result["server_time_hex"]), 12)  # 48 位 = 12 hex
        self.assertEqual(result["time_delta"], FUDGE + 1)

    def test_badkey_before_other_checks(self):
        signed, _ = sign(query())
        result = verify_tsig(payload(signed, key_name="other-key.example."))
        self.assertEqual(result["status"], "badkey")

    def test_badalg(self):
        signed, _ = sign(query(), algorithm="hmac-sha1.")
        result = verify_tsig(payload(signed))
        self.assertEqual(result["status"], "badalg")
        self.assertEqual(result["algorithm"], "hmac-sha1.")

    def test_badsig_wrong_secret(self):
        signed, _ = sign(query())
        result = verify_tsig(payload(signed, secret="definitely-wrong"))
        self.assertEqual(result["status"], "badsig")
        self.assertNotIn("definitely-wrong", json.dumps(result))

    def test_badsig_wrong_mac_length(self):
        # 31 字节 MAC（hmac-sha256 应为 32）：结构合法但长度不符 -> badsig
        signed, mac = sign(query())
        idx = signed.find(struct.pack("!H", 250))
        rdlength_pos = idx + 8
        rdata_start = idx + 10
        old_rdlength = struct.unpack_from("!H", signed, rdlength_pos)[0]
        # RDATA 尾部布局：MAC(32) + original_id(2) + error(2) + other_len(2)
        rdata_end = rdata_start + old_rdlength
        tail = signed[rdata_end - 6 : rdata_end]  # orig/err/otherlen
        mac_size_pos = rdata_end - 6 - 32 - 2
        head = signed[:mac_size_pos]
        rebuilt = (
            head
            + struct.pack("!H", 31)
            + mac[:31]
            + tail
        )
        rebuilt = (
            rebuilt[:rdlength_pos]
            + struct.pack("!H", old_rdlength - 1)
            + rebuilt[rdata_start:]
        )
        result = verify_tsig(payload(rebuilt))
        self.assertEqual(result["status"], "badsig")

    def test_check_order_badkey_then_badalg(self):
        # 算法与密钥名都错：必须先报 badkey
        signed, _ = sign(query(), algorithm="hmac-sha1.")
        result = verify_tsig(payload(signed, key_name="nope.example."))
        self.assertEqual(result["status"], "badkey")

    def test_response_requires_request_mac_prefix(self):
        req = query()
        signed_req, req_mac = sign(req)
        signed_resp, _ = sign(
            response(), request_mac=req_mac
        )
        # 提供正确 request_mac -> authenticated
        result = verify_tsig(payload(
            signed_resp,
            request_mac=base64.b64encode(req_mac).decode(),
        ))
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["request_mac_size"], 32)
        # 缺 request_mac：规范变量前缺少长度+内容 -> MAC 不一致 -> badsig
        self.assertEqual(
            verify_tsig(payload(signed_resp))["status"], "badsig"
        )
        # 错误 request_mac -> badsig
        self.assertEqual(
            verify_tsig(payload(
                signed_resp, request_mac=base64.b64encode(b"\x00" * 32).decode()
            ))["status"],
            "badsig",
        )

    def test_base64_secret_encoding(self):
        signed, _ = sign(query())
        result = verify_tsig(payload(
            signed,
            secret=base64.b64encode(SECRET).decode(),
            secret_encoding="base64",
        ))
        self.assertEqual(result["status"], "authenticated")

    def test_error_field_and_other_preserved(self):
        other = WHEN.to_bytes(6, "big")  # BADTIME 的 other 形如 48 位时间
        signed, _ = sign(query(), error=18, other=other)
        result = verify_tsig(payload(signed))
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["error"], 18)
        self.assertEqual(result["other_len"], 6)

    # ---- 结构错误：422 ----

    def test_missing_tsig(self):
        expect422(self, query(arcount=0), "missing_tsig")

    def test_multiple_tsig(self):
        signed, _ = sign(query())
        tsig_rr = signed[len(query()):]
        base = bytearray(query(arcount=2))
        expect422(self, bytes(base) + tsig_rr + tsig_rr, "multiple_tsig")

    def test_tsig_not_last(self):
        signed, _ = sign(query())
        tsig_rr = signed[len(query()):]
        base = bytearray(query(arcount=2))
        trailing = a_record(ttl=0)  # 附加区 TSIG 之后的普通记录
        expect422(self, bytes(base) + tsig_rr + trailing, "tsig_not_last")

    def test_tsig_in_answer_section(self):
        signed, _ = sign(query())
        tsig_rr = signed[len(query()):]
        moved = (
            struct.pack("!HHHHHH", MID, 0x8180, 1, 1, 0, 0)
            + question("www.example.com.") + tsig_rr
        )
        expect422(self, moved, "tsig_wrong_section")

    def test_bad_class_and_ttl(self):
        def mutate(rclass=255, ttl=0) -> bytes:
            signed, _ = sign(query())
            idx = signed.find(struct.pack("!H", 250))
            b = bytearray(signed)
            struct.pack_into("!H", b, idx + 2, rclass)
            struct.pack_into("!I", b, idx + 4, ttl)
            return bytes(b)

        expect422(self, mutate(rclass=1), "tsig_bad_class")
        expect422(self, mutate(ttl=1), "tsig_bad_ttl")

    def test_original_id_mismatch(self):
        signed, _ = sign(query())
        b = bytearray(signed)
        struct.pack_into("!H", b, 0, 0x9999)
        expect422(self, bytes(b), "tsig_original_id_mismatch")

    def test_truncations(self):
        signed, _ = sign(query())
        expect422(self, b"\x00" * 5, "message_truncated")
        expect422(self, signed[:-1], "message_truncated")
        expect422(self, signed[:20], "message_truncated")

    def test_trailing_bytes(self):
        signed, _ = sign(query())
        expect422(self, signed + b"\x00", "message_trailing_bytes")

    def test_compression_pointer_oob_and_loop(self):
        q = query()
        oob = bytearray(q)
        oob[12] = 0xC0
        oob[13] = 0xFF
        expect422(self, bytes(oob), "compression_pointer_out_of_bounds")

        owner_off = len(q)
        loop = bytearray(q)
        loop.extend(struct.pack("!H", 0xC000 | owner_off))
        loop.extend(struct.pack("!HHIH", 250, 255, 0, 0))
        expect422(self, bytes(loop), "compression_pointer_loop")

    def test_compressed_owner_and_algorithm_are_parsed(self):
        # owner 用帧内合法压缩指针指向问题区里的 example.com.
        signed, _ = sign(query(), key_name="tsigkey.example.com.")
        idx = signed.find(struct.pack("!H", 250))
        owner_len = idx - len(query())
        compressed_owner = b"\x07tsigkey" + struct.pack("!H", 0xC000 | 16)
        rebuilt = (
            signed[: len(query())] + compressed_owner
            + signed[len(query()) + owner_len :]
        )
        result = verify_tsig(payload(
            rebuilt, key_name="tsigkey.example.com."
        ))
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["key_name"], "tsigkey.example.com.")

    # ---- 请求格式：400 ----

    def test_invalid_request_shapes(self):
        signed, _ = sign(query())
        good = payload(signed)
        cases = [
            {},
            {"**": "x"},
            {**good, "message": "not base64!!"},
            {**good, "now": -1},
            {**good, "now": 2**48},
            {**good, "now": 1.5},
            {**good, "now": True},
            {**good, "now": "1700000100"},
            {**good, "secret": ""},
            {**good, "secret": 123},
            {**good, "secret_encoding": "hex"},
            {**good, "key_name": ""},
            {**good, "key_name": "bad name!"},
            {**good, "request_mac": "@@"},
        ]
        for case in cases:
            with self.subTest(case=list(case.keys())):
                with self.assertRaises(ReviewError) as ctx:
                    verify_tsig(case)
                self.assertEqual(ctx.exception.status, 400, case)

    def test_deterministic_output(self):
        signed, _ = sign(query())
        a = verify_tsig(payload(signed))
        b = verify_tsig(payload(signed))
        self.assertEqual(json.dumps(a, sort_keys=True),
                         json.dumps(b, sort_keys=True))


# ---------------------------------------------------------------------------
# 独立固定向量：按 RFC 8945 §5.2 由独立脚本（不导入 app.tsig）一次性生成
# 并冻结；旧实现（变量区写 Original ID/MAC Size、漏 key_name/CLASS/TTL、
# request_mac 位置错误）对以下向量一律误报 badsig。
# ---------------------------------------------------------------------------

FIXED_REQ_SHA256 = {
    "message": "vu8BAAABAAAAAAABBWZpeGVkB2V4YW1wbGUAAAEAAQlmaXhlZC1rZXkHZXhhbXBsZQAA+gD/AAAAAAA9C2htYWMtc2hhMjU2AAAAaNnewAEsACADi2/LfY20BLK2uHRZSgU591ipykTdLc6g+8gET4eWqb7vAAAAAA==",
    "secret": "fixed-vector-secret",
    "key_name": "fixed-key.example.",
    "now": 1759108860,
    "mac_hex": "038b6fcb7d8db404b2b6b874594a0539f758a9ca44dd2dcea0fbc8044f8796a9",
}

FIXED_RESP_SHA256 = {
    "message": "vu+BgAABAAEAAAABBWZpeGVkB2V4YW1wbGUAAAEAAQVmaXhlZAdleGFtcGxlAAABAAEAAAA8AATAAAJjCWZpeGVkLWtleQdleGFtcGxlAAD6AP8AAAAAAD0LaG1hYy1zaGEyNTYAAABo2d7FASwAIOSrT/WICuYP3zF0HJ54GgKlGCy0VsbGUK+pzMblk9Nmvu8AAAAA",
    "secret": "fixed-vector-secret",
    "key_name": "fixed-key.example.",
    "now": 1759108835,
    "request_mac": "A4tvy32NtASytrh0WUoFOfdYqcpE3S3OoPvIBE+Hlqk=",
    "mac_hex": "e4ab4ff5880ae60fdf31741c9e781a02a5182cb456c6c650afa9ccc6e593d366",
}

FIXED_REQ_SHA512 = {
    "message": "yv4BAAABAAAAAAABCGZpeGVkNTEyB2V4YW1wbGUAAAEAAQlmaXhlZC1rZXkHZXhhbXBsZQAA+gD/AAAAAABdC2htYWMtc2hhNTEyAAAAaNnfJAEsAEBe7tzINkGWUoD0ibmUrvawxCODkBvbee3amnbKiRl9RCcsVPo1/OfufJJ2ETt7skhZFmAw5geZC9MdO3V8CFkUyv4AAAAA",
    "secret": "fixed-vector-secret-512",
    "key_name": "fixed-key.example.",
    "now": 1759108910,
    "mac_hex": "5eeedcc83641965280f489b994aef6b0c42383901bdb79edda9a76ca89197d44272c54fa35fce7ee7c9276113b7bb24859166030e607990bd31d3b757c085914",
}


def embedded_mac(message: bytes, mac_size: int) -> bytes:
    """从 TSIG RDATA 尾部取 MAC（这些向量 other_len=0，MAC 恰在末尾
    original_id(2)+error(2)+other_len(2) 共 6 字节之前）。"""
    return message[-(6 + mac_size):-6]


class TsigFixedVectorTests(unittest.TestCase):
    """冻结的 RFC 8945 §5.2 向量：普通请求 / 带 request_mac 的响应 /
    双算法 / 单字节篡改。"""

    @staticmethod
    def _payload(vector: dict) -> dict:
        return {k: v for k, v in vector.items() if k != "mac_hex"}

    def test_fixed_request_sha256(self):
        result = verify_tsig(self._payload(FIXED_REQ_SHA256))
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["mac_size"], 32)
        raw = base64.b64decode(FIXED_REQ_SHA256["message"])
        self.assertEqual(
            embedded_mac(raw, 32).hex(), FIXED_REQ_SHA256["mac_hex"]
        )

    def test_fixed_response_with_request_mac(self):
        result = verify_tsig(self._payload(FIXED_RESP_SHA256))
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["request_mac_size"], 32)
        raw = base64.b64decode(FIXED_RESP_SHA256["message"])
        self.assertEqual(
            embedded_mac(raw, 32).hex(), FIXED_RESP_SHA256["mac_hex"]
        )
        # 同一响应缺 request_mac 前缀 -> HMAC 输入不同 -> badsig
        without = self._payload(FIXED_RESP_SHA256)
        del without["request_mac"]
        self.assertEqual(verify_tsig(without)["status"], "badsig")

    def test_fixed_request_sha512(self):
        result = verify_tsig(self._payload(FIXED_REQ_SHA512))
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["algorithm"], "hmac-sha512.")
        self.assertEqual(result["mac_size"], 64)
        raw = base64.b64decode(FIXED_REQ_SHA512["message"])
        self.assertEqual(
            embedded_mac(raw, 64).hex(), FIXED_REQ_SHA512["mac_hex"]
        )

    def test_fixed_single_byte_tamper(self):
        base = self._payload(FIXED_REQ_SHA256)
        # 问题区 qname 单字节篡改
        raw = bytearray(base64.b64decode(base["message"]))
        raw[20] ^= 0x01
        tampered = {**base, "message": base64.b64encode(bytes(raw)).decode()}
        self.assertEqual(verify_tsig(tampered)["status"], "badsig")
        # MAC 内单字节篡改（末尾 6 字节为 original_id/error/other_len）
        raw = bytearray(base64.b64decode(base["message"]))
        raw[-7] ^= 0x01
        tampered = {**base, "message": base64.b64encode(bytes(raw)).decode()}
        self.assertEqual(verify_tsig(tampered)["status"], "badsig")


class TsigApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = build_server("127.0.0.1", 0, ":memory:")
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                     daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _post(self, body: dict):
        req = urllib.request.Request(
            self.base + "/api/tsig/verify",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_authenticated_over_http(self):
        signed, _ = sign(query())
        status, body = self._post(payload(signed))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["tsig"]["status"], "authenticated")

    def test_badtime_is_200_terminal(self):
        signed, _ = sign(query())
        status, body = self._post(payload(signed, now=WHEN + FUDGE + 1))
        self.assertEqual(status, 200)
        tsig = body["tsig"]
        self.assertEqual(tsig["status"], "badtime")
        self.assertEqual(tsig["server_time"], WHEN + FUDGE + 1)

    def test_structure_error_is_422_over_http(self):
        status, body = self._post(payload(query(arcount=0)))
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "missing_tsig")

    def test_bad_request_is_400_over_http(self):
        status, body = self._post({"message": "x"})
        self.assertEqual(status, 400, body)
        self.assertEqual(body["error"]["code"], "invalid_request")

    def test_response_with_request_mac_over_http(self):
        signed_req, req_mac = sign(query())
        signed_resp, _ = sign(response(), request_mac=req_mac)
        status, body = self._post(payload(
            signed_resp, request_mac=base64.b64encode(req_mac).decode()
        ))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["tsig"]["status"], "authenticated")


if __name__ == "__main__":
    unittest.main()
