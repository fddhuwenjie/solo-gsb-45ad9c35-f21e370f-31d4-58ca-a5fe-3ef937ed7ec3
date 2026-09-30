"""app.wire 共享 DNS wire 解析层回归测试。

用合法、多级嵌套压缩指针与畸形报文三类向量直接回归共享层：

- 规范名称 + 消费后偏移 + 原始 RR 边界三件套（owner 与 RDATA 内的
  压缩指针都要支持）；
- 两种截断错误码（AXFR 的 frame_truncated 与 TSIG 的
  message_truncated）下，成环/越界/截断的错误码与定位文案一致。
"""

import struct
import unittest

from app.review import ReviewError
from app.wire import (
    HEADER_SIZE,
    RRView,
    WireCursor,
    parse_header,
    read_name,
)


def wname(name: str) -> bytes:
    if name == ".":
        return b"\x00"
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def ptr(offset: int) -> bytes:
    return struct.pack("!H", 0xC000 | offset)


def header(mid=1, qd=0, an=0, ns=0, ar=0, flags=0x8000) -> bytes:
    return struct.pack("!HHHHHH", mid, flags, qd, an, ns, ar)


def rr(owner: bytes, rtype: int, rdata: bytes, rclass=1, ttl=300) -> bytes:
    return owner + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


class ReadNameTests(unittest.TestCase):
    def test_uncompressed_root_and_fqdn(self):
        buf = wname("example.com.")
        parsed = read_name(buf, 0, "定位")
        self.assertEqual(parsed.name, "example.com.")
        self.assertEqual(parsed.next_offset, len(buf))

    def test_root_name(self):
        parsed = read_name(b"\x00", 0, "定位")
        self.assertEqual(parsed.name, ".")
        self.assertEqual(parsed.next_offset, 1)

    def test_case_folded_to_lower(self):
        buf = b"\x03WWW\x07Example\x03Com\x00"
        self.assertEqual(read_name(buf, 0, "x").name, "www.example.com.")

    def test_simple_pointer_returns_offset_after_pointer(self):
        # 偏移 0 放完整名（13 字节），偏移 20 用两字节指针引用
        base = wname("example.com.")
        buf = base + b"\x00" * (20 - len(base)) + ptr(0)
        parsed = read_name(buf, 20, "定位")
        self.assertEqual(parsed.name, "example.com.")
        # 消费后的偏移必须是指针后（22），而非被指名称末尾（13）
        self.assertEqual(parsed.next_offset, 22)

    def test_nested_pointer_chain(self):
        # 偏移 0: example.com. ；偏移 30: \x03www + ptr(0)；
        # 偏移 50: \x03host\x03sub + ptr(30)（两级嵌套，跨名称）
        buf = bytearray(60)
        base = wname("example.com.")
        buf[0:len(base)] = base
        mid = b"\x03www" + ptr(0)
        buf[30:30 + len(mid)] = mid
        top = b"\x04host\x03sub" + ptr(30)
        buf[50:50 + len(top)] = top
        parsed = read_name(bytes(buf), 50, "定位")
        self.assertEqual(parsed.name, "host.sub.www.example.com.")
        self.assertEqual(parsed.next_offset, 50 + len(top))

    # ---- 畸形向量 ----

    def test_self_pointer_is_loop(self):
        buf = ptr(0)
        with self.assertRaises(ReviewError) as ctx:
            read_name(buf, 0, "定位A")
        self.assertEqual(ctx.exception.code, "compression_pointer_loop")
        self.assertIn("定位A", ctx.exception.message)
        self.assertIn("偏移 0", ctx.exception.message)

    def test_two_node_pointer_cycle(self):
        buf = ptr(2) + ptr(0)
        with self.assertRaises(ReviewError) as ctx:
            read_name(buf, 0, "定位B")
        self.assertEqual(ctx.exception.code, "compression_pointer_loop")
        self.assertIn("定位B", ctx.exception.message)

    def test_pointer_out_of_bounds(self):
        buf = ptr(0x3FFF)
        with self.assertRaises(ReviewError) as ctx:
            read_name(buf, 0, "定位C")
        self.assertEqual(ctx.exception.code,
                         "compression_pointer_out_of_bounds")
        self.assertIn("16383", ctx.exception.message)

    def test_truncated_label_and_half_pointer_use_injected_code(self):
        for code in ("frame_truncated", "message_truncated"):
            with self.subTest(code=code):
                with self.assertRaises(ReviewError) as ctx:
                    read_name(b"\x07ab", 0, "定位D", truncated_code=code)
                self.assertEqual(ctx.exception.code, code)
                self.assertIn("定位D", ctx.exception.message)
                with self.assertRaises(ReviewError) as ctx:
                    read_name(b"\xc0", 0, "定位E", truncated_code=code)
                self.assertEqual(ctx.exception.code, code)
                self.assertIn("半个字节", ctx.exception.message)

    def test_reserved_label_type_is_invalid_name(self):
        with self.assertRaises(ReviewError) as ctx:
            read_name(b"\x41x", 0, "定位F")
        self.assertEqual(ctx.exception.code, "invalid_name")
        self.assertIn("0x41", ctx.exception.message)


class HeaderTests(unittest.TestCase):
    def test_parses_flags(self):
        # 0x8380: QR=1, AA=1, TC=1, RCODE=0
        h = parse_header(header(0x1234, 1, 2, 3, 4, 0x8380),
                         "frame_truncated", "第 1 帧：")
        self.assertEqual(h.message_id, 0x1234)
        self.assertTrue(h.qr)
        self.assertEqual(h.opcode, 0)
        self.assertTrue(h.tc)
        self.assertEqual(h.rcode, 0)
        self.assertEqual((h.qdcount, h.ancount, h.nscount, h.arcount),
                         (1, 2, 3, 4))

    def test_short_header_keeps_code_and_prefix(self):
        for code, where in (("frame_truncated", "第 2 帧："),
                            ("message_truncated", "")):
            with self.assertRaises(ReviewError) as ctx:
                parse_header(b"\x00" * 5, code, where)
            self.assertEqual(ctx.exception.code, code)
            self.assertIn("DNS 头不足 12 字节", ctx.exception.message)
            if where:
                self.assertTrue(ctx.exception.message.startswith(where))


class CursorQuestionTests(unittest.TestCase):
    def test_question_round_trip(self):
        buf = header(qd=1) + wname("www.example.com.") + struct.pack("!HH", 1, 1)
        cur = WireCursor(buf, "frame_truncated")
        q = cur.read_question("第 1 帧 问题区", "第 1 帧：问题区 QTYPE/QCLASS 截断")
        self.assertEqual((q.qname, q.qtype, q.qclass),
                         ("www.example.com.", 1, 1))
        self.assertTrue(cur.at_end())

    def test_question_fixed_part_truncated(self):
        buf = header(qd=1) + wname("www.example.com.") + b"\x00\x01"
        cur = WireCursor(buf, "message_truncated")
        with self.assertRaises(ReviewError) as ctx:
            cur.read_question("问题区第 1 项名称",
                              "问题区第 1 项 QTYPE/QCLASS 截断")
        self.assertEqual(ctx.exception.code, "message_truncated")


class CursorRRTests(unittest.TestCase):
    def _wire_with_rr(self, rdata: bytes) -> tuple[bytes, int]:
        body = rr(wname("ns.example.com."), 16, rdata)
        buf = header(an=1) + body
        return buf, HEADER_SIZE

    def test_open_rr_returns_raw_boundaries(self):
        txt = bytes([5]) + b"hello"
        buf, rr_start = self._wire_with_rr(txt)
        cur = WireCursor(buf, "frame_truncated")
        view = cur.open_rr("第 1 帧 回答区", "第 1 帧：第 1 条回答的记录头截断")
        self.assertIsInstance(view, RRView)
        self.assertEqual(view.owner, "ns.example.com.")
        self.assertEqual((view.rtype, view.rclass, view.ttl, view.rdlength),
                         (16, 1, 300, 6))
        # 原始 RR 边界
        self.assertEqual(view.start, rr_start)
        self.assertEqual(view.rdata_end - view.rdata_start, 6)
        self.assertEqual(buf[view.rdata_start:view.rdata_end], txt)
        self.assertEqual(view.next_offset, view.rdata_end)
        self.assertTrue(cur.at_end())
        # 边界检查不改动原报文
        cur.require_rdata(view, "记录")
        cur.check_ttl(view, "记录")

    def test_compressed_owner_boundary_is_two_bytes(self):
        body = rr(ptr(12), 1, b"\x01\x02\x03\x04")
        buf = header(qd=1, an=1) + wname("example.com.") + struct.pack("!HH", 252, 1) + body
        cur = WireCursor(buf, "frame_truncated")
        cur.read_question("q", "qt")
        view = cur.open_rr("回答区", "记录头截断")
        self.assertEqual(view.owner, "example.com.")
        # owner 只占 2 字节指针：RR 起点到固定头距离必须是 2
        self.assertEqual(view.rdata_start - view.start, 2 + 10)
        self.assertEqual(buf[view.rdata_start:view.rdata_end],
                         b"\x01\x02\x03\x04")

    def test_nested_pointer_inside_rdata(self):
        # 手工布局多级嵌套指针链，验证 owner 与“RDATA 内”名称同规则
        buf = bytearray(90)
        struct.pack_into("!HHHHHH", buf, 0, 1, 0x8000, 0, 0, 0, 0)
        # 偏移 30: example.com.
        base = wname("example.com.")
        buf[30:30 + len(base)] = base
        # 偏移 60: \x03sub + ptr(30) -> sub.example.com.
        mid = b"\x03sub" + ptr(30)
        buf[60:60 + len(mid)] = mid
        parsed = read_name(bytes(buf), 60, "RDATA 名称")
        self.assertEqual(parsed.name, "sub.example.com.")
        # 再来一级：偏移 12: \x04host + ptr(60)
        top = b"\x04host" + ptr(60)
        buf[12:12 + len(top)] = top
        parsed = read_name(bytes(buf), 12, "owner")
        self.assertEqual(parsed.name, "host.sub.example.com.")
        self.assertEqual(parsed.next_offset, 12 + len(top))

    def test_checks_in_caller_order_head_then_ttl_then_rdata(self):
        # 固定头截断：open_rr 立即报错
        buf = header(an=1) + wname("a.example.") + b"\x00\x01"
        cur = WireCursor(buf, "frame_truncated")
        with self.assertRaises(ReviewError) as ctx:
            cur.open_rr("回答区", "定制记录头文案")
        self.assertEqual(ctx.exception.message, "定制记录头文案")

        # TTL 超界：open_rr 本身不报，check_ttl 才报
        body = rr(wname("a.example."), 16, b"\x05hello", ttl=2**31)
        buf = header(an=1) + body
        cur = WireCursor(buf, "message_truncated")
        view = cur.open_rr("回答区第 1 条记录", "记录头截断")
        with self.assertRaises(ReviewError) as ctx:
            cur.check_ttl(view, "回答区第 1 条记录")
        self.assertEqual(ctx.exception.code, "invalid_record")

        # RDATA 越界：require_rdata 报截断码
        body = wname("a.example.") + struct.pack("!HHIH", 16, 1, 300, 50) + b"x"
        buf = header(an=1) + body
        cur = WireCursor(buf, "frame_truncated")
        view = cur.open_rr("回答区", "记录头截断")
        with self.assertRaises(ReviewError) as ctx:
            cur.require_rdata(view, "第 1 帧 第 1 条回答（a.example. TXT）")
        self.assertEqual(ctx.exception.code, "frame_truncated")
        self.assertIn("RDATA 超出报文末尾", ctx.exception.message)

    def test_trailing_count(self):
        buf = header() + b"\xaa\xbb"
        cur = WireCursor(buf, "message_truncated")
        self.assertFalse(cur.at_end())
        self.assertEqual(cur.trailing_count(), 2)


if __name__ == "__main__":
    unittest.main()
