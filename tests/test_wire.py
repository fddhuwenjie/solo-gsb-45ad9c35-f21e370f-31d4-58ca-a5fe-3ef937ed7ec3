"""共享 wire 遍历层（app.wire）单元测试。

报文现场构造，覆盖：合法全名/压缩名、多层嵌套压缩指针（owner 与
RDATA 内）、指针成环（自指与嵌套环）、越界、半个指针、标签截断、
问题区/RR 游标边界与尾随字节，以及两个入口的截断码区分。
"""

import struct
import unittest

from app.review import ReviewError
from app.wire import MAX_TTL, RawRR, WireQuestion, WireReader


def pack_name(name: str) -> bytes:
    if name == ".":
        return b"\x00"
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def ptr(target: int) -> bytes:
    return struct.pack("!H", 0xC000 | target)


def header(qd=0, an=0, ns=0, ar=0, mid=0x1234, flags=0x8000) -> bytes:
    return struct.pack("!HHHHHH", mid, flags, qd, an, ns, ar)


def rr(name_wire: bytes, rtype=1, rclass=1, ttl=60, rdata=b"") -> bytes:
    return name_wire + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


class NameDecompressionTests(unittest.TestCase):
    def test_plain_absolute_and_root_name(self):
        msg = header() + pack_name("WWW.Example.COM.") + pack_name(".")
        reader = WireReader(msg, "frame_truncated")
        name, after = reader.read_name(12, "x")
        self.assertEqual(name, "www.example.com.")
        self.assertEqual(after, 12 + len(pack_name("www.example.com.")))
        root, root_after = reader.read_name(after, "x")
        self.assertEqual(root, ".")
        self.assertEqual(root_after, after + 1)

    def test_single_pointer_consumes_two_bytes(self):
        # 偏移 12 放全名，名称之后以指针引用它：消费偏移只前进 2
        full = pack_name("example.com.")
        msg = header() + full + ptr(12)
        reader = WireReader(msg, "frame_truncated")
        name, after = reader.read_name(12 + len(full), "owner")
        self.assertEqual(name, "example.com.")
        self.assertEqual(after, 12 + len(full) + 2)

    def test_nested_pointer_chain(self):
        # 12: "\x03www" 指针(18)
        # 18: "\x03ns2" 指针(24)
        # 24: "\x03com\x00"  —— 两跳指针拼出 www.ns2.com.
        target_ns2, target_com = 18, 24
        msg = (
            header()
            + b"\x03www" + ptr(target_ns2)
            + b"\x03ns2" + ptr(target_com)
            + b"\x03com\x00"
        )
        reader = WireReader(msg, "frame_truncated")
        name, after = reader.read_name(12, "chain")
        self.assertEqual(name, "www.ns2.com.")
        self.assertEqual(after, 12 + 1 + 3 + 2)

    def test_pointer_target_inside_pointer_is_followed(self):
        # 12: "\x04mail" 指针(19)；19: "\x03mx1" 指针(25)；25: "\x03net\x00"
        p1, p2 = 19, 25
        msg = (
            header()
            + b"\x04mail" + ptr(p1)
            + b"\x03mx1" + ptr(p2)
            + b"\x03net\x00"
        )
        name, after = WireReader(msg, "message_truncated").read_name(12, "x")
        self.assertEqual(name, "mail.mx1.net.")
        self.assertEqual(after, 12 + 5 + 2)

    def test_self_pointer_loop(self):
        msg = header() + ptr(12)
        with self.assertRaises(ReviewError) as ctx:
            WireReader(msg, "frame_truncated").read_name(12, "问题区")
        self.assertEqual(ctx.exception.code, "compression_pointer_loop")
        self.assertIn("问题区", ctx.exception.message)

    def test_nested_pointer_loop(self):
        # 12 -> 14 -> 12
        msg = header() + ptr(14) + ptr(12)
        with self.assertRaises(ReviewError) as ctx:
            WireReader(msg, "message_truncated").read_name(12, "owner")
        self.assertEqual(ctx.exception.code, "compression_pointer_loop")

    def test_pointer_out_of_bounds(self):
        msg = header() + ptr(0x3FFF)
        with self.assertRaises(ReviewError) as ctx:
            WireReader(msg, "frame_truncated").read_name(12, "回答区")
        self.assertEqual(ctx.exception.status, 422)
        self.assertEqual(ctx.exception.code,
                         "compression_pointer_out_of_bounds")
        self.assertIn("16383", ctx.exception.message)

    def test_half_pointer_and_label_truncation_map_to_caller_code(self):
        half = header() + b"\xc0"
        with self.assertRaises(ReviewError) as ctx:
            WireReader(half, "frame_truncated").read_name(12, "x")
        self.assertEqual(ctx.exception.code, "frame_truncated")
        with self.assertRaises(ReviewError) as ctx:
            WireReader(half, "message_truncated").read_name(12, "x")
        self.assertEqual(ctx.exception.code, "message_truncated")

        label = header() + b"\x07abc"
        with self.assertRaises(ReviewError) as ctx:
            WireReader(label, "message_truncated").read_name(12, "y")
        self.assertEqual(ctx.exception.code, "message_truncated")
        self.assertIn("y", ctx.exception.message)

    def test_reserved_label_type_and_non_ascii(self):
        msg = header() + b"\x40ab"
        with self.assertRaises(ReviewError) as ctx:
            WireReader(msg, "frame_truncated").read_name(12, "z")
        self.assertEqual(ctx.exception.code, "invalid_name")

        msg = header() + b"\x02\xff\xfe\x00"
        with self.assertRaises(ReviewError) as ctx:
            WireReader(msg, "frame_truncated").read_name(12, "z")
        self.assertEqual(ctx.exception.code, "invalid_name")


class QuestionAndRRCursorTests(unittest.TestCase):
    def test_open_rejects_short_header_with_caller_code(self):
        for code in ("frame_truncated", "message_truncated"):
            with self.assertRaises(ReviewError) as ctx:
                WireReader.open(b"\x00" * 5, code, "DNS 头不足 12 字节")
            self.assertEqual(ctx.exception.code, code)
            self.assertIn("实际 5 字节", ctx.exception.message)

    def test_read_question_returns_canonical_question(self):
        msg = header(qd=1) + pack_name("WWW.Example.COM.") + struct.pack(
            "!HH", 252, 1
        )
        reader, head = WireReader.open(msg, "frame_truncated", "head")
        self.assertEqual(head["qdcount"], 1)
        question = reader.read_question("第 1 帧 问题区", "q 截断")
        self.assertIsInstance(question, WireQuestion)
        self.assertEqual(
            question.as_tuple(), ("www.example.com.", 252, 1)
        )
        self.assertEqual(reader.pos, len(msg))

    def test_read_question_truncated(self):
        msg = header(qd=1) + pack_name("example.com.") + b"\x00"
        reader, _ = WireReader.open(msg, "message_truncated", "head")
        with self.assertRaises(ReviewError) as ctx:
            reader.read_question("问题区第 1 项名称", "qtype/qclass 截断")
        self.assertEqual(ctx.exception.code, "message_truncated")

    def test_read_rr_returns_raw_boundaries_and_advances(self):
        owner = pack_name("a.example.")
        rdata = pack_name("b.example.")
        body = rr(owner, rtype=2, ttl=300, rdata=rdata)
        msg = header(an=1) + body
        reader, _ = WireReader.open(msg, "frame_truncated", "head")
        rec = reader.read_rr("回答区第 1 条记录", "记录头截断")
        self.assertIsInstance(rec, RawRR)
        self.assertEqual(rec.start, 12)
        self.assertEqual(rec.rdata_start, 12 + len(owner) + 10)
        self.assertEqual(rec.rdata_end, 12 + len(body))
        self.assertEqual(rec.end, 12 + len(body))
        self.assertEqual((rec.rtype, rec.rclass, rec.ttl, rec.rdlength),
                         (2, 1, 300, len(rdata)))
        self.assertEqual(rec.owner, "a.example.")
        self.assertEqual(reader.pos, len(msg))
        reader.require_rdata_within(rec, "不应越界")
        reader.require_end("message_trailing_bytes", "各区解析后")

    def test_read_rr_keeps_ttl_and_rdata_bounds_for_caller(self):
        # 共享游标不判定 TTL/RDATA：TTL=2^31、RDATA 越界都能切出边界，
        # 由调用方按自己的顺序与文案报错。
        owner = pack_name("a.example.")
        msg = header(an=1) + owner + struct.pack("!HHIH", 1, 1, 2**31, 99)
        reader, _ = WireReader.open(msg, "message_truncated", "head")
        rec = reader.read_rr("附加区第 1 条记录", "记录头截断")
        self.assertEqual(rec.ttl, MAX_TTL + 1)
        with self.assertRaises(ReviewError) as ctx:
            reader.require_rdata_within(rec, "附加区第 1 条记录：RDATA 超出报文末尾")
        self.assertEqual(ctx.exception.code, "message_truncated")
        self.assertIn("附加区第 1 条记录", ctx.exception.message)

    def test_trailing_bytes(self):
        msg = header() + b"\x00"
        reader, _ = WireReader.open(msg, "message_truncated", "head")
        with self.assertRaises(ReviewError) as ctx:
            reader.require_end("message_trailing_bytes", "各区解析后")
        self.assertEqual(ctx.exception.code, "message_trailing_bytes")
        self.assertIn("各区解析后", ctx.exception.message)
        self.assertIn("1 个尾随字节", ctx.exception.message)

    def test_compressed_owner_and_rdata_name_share_rules(self):
        # owner 与 RDATA 内名称都用指针；游标边界仍按 2 字节指针计算
        full = pack_name("example.com.")  # 位于偏移 12（名字池，不在任何区）
        name_pool_end = 12 + len(full)
        rdata = b"\x03www" + ptr(12)  # www + 指向 example.com.
        body = rr(ptr(12), rtype=5, rdata=rdata)
        msg = header(an=1) + full + body
        reader, _ = WireReader.open(msg, "frame_truncated", "head")
        reader.pos = name_pool_end  # RR 位于名字池之后
        rec = reader.read_rr("回答区第 1 条记录", "记录头截断")
        self.assertEqual(rec.owner, "example.com.")
        cname, after = reader.read_name(rec.rdata_start, "rdata")
        self.assertEqual(cname, "www.example.com.")
        self.assertEqual(after, rec.rdata_start + 4 + 2)
        self.assertEqual(after, rec.rdata_end)


if __name__ == "__main__":
    unittest.main()
