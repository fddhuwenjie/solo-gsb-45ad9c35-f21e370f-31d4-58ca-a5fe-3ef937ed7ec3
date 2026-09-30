"""DNS wire 解析共享层（RFC 1035 §4.1.1–4.1.4）。

为 :mod:`app.axfr`（TCP 区传送响应流）与 :mod:`app.tsig`（RFC 8945
报文校验）提供同一套：

- 名称解压 :func:`read_name`（支持 owner 与 RDATA 内的压缩指针、跨区
  与跨记录引用、多级嵌套指针、成环检测）；
- 问题区游标 :meth:`WireCursor.read_question`；
- RR 游标 :meth:`WireCursor.open_rr`：只做结构解析，返回的
  :class:`RRView` 同时携带规范 owner、消费后的偏移与**原始 RR 边界**
  （``start`` / ``rdata_start`` / ``rdata_end``，均指向未改动的原报文
  字节，供 TSIG 按原边界切分 HMAC 输入）。

两个接口的错误码不同（AXFR 用 ``frame_truncated``，TSIG 用
``message_truncated``），因此截断错误码由调用方通过 ``truncated_code``
注入；压缩指针成环/越界、非法名称等语义错误的错误码两端一致。所有
定位文案（``where`` 前缀）也由调用方传入，共享层只负责拼接固定后缀，
从而保持两个接口既有的错误码与定位文案不变。

各区与各字段的**检查顺序**仍完全由调用方掌握：:meth:`open_rr` 只读
owner 与 10 字节固定头、报告原始 RDATA 边界，TTL 范围与 RDATA 越界
检查由调用方在各自的时机（AXFR 在类型支持判定之后）显式调用
:meth:`check_ttl` / :meth:`require_rdata`。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .review import ReviewError
from .zoneparse import ZoneParseError, validate_name

HEADER_SIZE = 12
RECORD_FIXED_SIZE = 10  # TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
MAX_TTL = 2**31 - 1


@dataclass(frozen=True)
class ParsedName:
    """一次名称解压的结果。

    ``name`` 为小写绝对规范名；``next_offset`` 为名称在**所在字段**中
    消费完毕后的下一偏移（遇到压缩指针时为指针后一位置，而非被指名称
    处）。``next_offset`` 同时就是名称编码在字段内的原始结束边界：多
    级指针只记首次跳转点，字段其余部分一律从该偏移继续。
    """

    name: str
    next_offset: int


@dataclass(frozen=True)
class Header:
    message_id: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    @property
    def qr(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0xF

    @property
    def tc(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def rcode(self) -> int:
        return self.flags & 0xF


@dataclass(frozen=True)
class Question:
    qname: str
    qtype: int
    qclass: int


@dataclass(frozen=True)
class RRView:
    """一条 RR 的结构视图（不解释 RDATA 内容）。

    边界均相对整个报文（AXFR 为单个帧体）：

    - ``start``：owner 编码起始（原始 RR 边界起点）；
    - ``rdata_start`` / ``rdata_end``：RDATA 在原报文中的字节区间
      （半开区间），RDATA 内名称的压缩指针可指向区间之外；
    - 游标在 :meth:`open_rr` 返回时已推进到 ``rdata_end``。
    """

    owner: str
    rtype: int
    rclass: int
    ttl: int
    rdlength: int
    start: int
    rdata_start: int
    rdata_end: int

    @property
    def next_offset(self) -> int:
        return self.rdata_end


# ---------------------------------------------------------------------------
# 名称解压（RFC 1035 §4.1.4）
# ---------------------------------------------------------------------------

def read_name(
    buf: bytes,
    offset: int,
    where: str,
    truncated_code: str = "frame_truncated",
) -> ParsedName:
    """在 ``offset`` 处读取一个（可压缩的）域名。

    返回规范小写绝对名与消费后的下一偏移。指针成环/越界、截断、标签
    类型非法、名称含非 ASCII 或无法规范化为合法主机名均抛
    :class:`ReviewError`（422）；截断类错误的错误码由
    ``truncated_code`` 决定（AXFR=``frame_truncated``、
    TSIG=``message_truncated``）。
    """
    labels: list[str] = []
    pos = offset
    end: int | None = None  # 首次跟随压缩指针后确定的“下一偏移”
    visited: set[int] = set()  # 已跳转过的指针目标（环检测）
    while True:
        if pos >= len(buf):
            raise ReviewError(
                truncated_code, f"{where}：名称超出报文末尾", 422
            )
        length = buf[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise ReviewError(
                    truncated_code, f"{where}：压缩指针只有半个字节", 422
                )
            target = ((length & 0x3F) << 8) | buf[pos + 1]
            if target >= len(buf):
                raise ReviewError(
                    "compression_pointer_out_of_bounds",
                    f"{where}：压缩指针指向报文外偏移 {target}",
                    422,
                )
            if end is None:
                end = pos + 2
            if target in visited:
                raise ReviewError(
                    "compression_pointer_loop",
                    f"{where}：压缩指针在偏移 {target} 处成环",
                    422,
                )
            visited.add(target)
            pos = target
            continue
        if length & 0xC0:
            raise ReviewError(
                "invalid_name",
                f"{where}：非法标签类型字节 0x{length:02x}",
                422,
            )
        pos += 1
        if length == 0:
            break
        if pos + length > len(buf):
            raise ReviewError(
                truncated_code, f"{where}：标签超出报文末尾", 422
            )
        raw = buf[pos : pos + length]
        try:
            labels.append(raw.decode("ascii").lower())
        except UnicodeDecodeError as exc:
            raise ReviewError(
                "invalid_name",
                f"{where}：名称标签含非 ASCII 字节: {exc}",
                422,
            ) from exc
        pos += length
    name = (".".join(labels) + ".") if labels else "."
    try:
        validate_name(name)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_name", f"{where}：名称非法: {exc}", 422
        ) from exc
    return ParsedName(
        name=name, next_offset=(end if end is not None else pos)
    )


# ---------------------------------------------------------------------------
# 头解析
# ---------------------------------------------------------------------------

def parse_header(buf: bytes, truncated_code: str, where: str) -> Header:
    """解析 12 字节 DNS 头（RFC 1035 §4.1.1），不足 12 字节为截断错误。

    ``where`` 为定位前缀：AXFR 传 ``"第 N 帧："``，TSIG 传 ``""``。
    """
    if len(buf) < HEADER_SIZE:
        raise ReviewError(
            truncated_code,
            f"{where}DNS 头不足 12 字节（实际 {len(buf)} 字节）",
            422,
        )
    return Header(*struct.unpack("!HHHHHH", buf[:HEADER_SIZE]))


# ---------------------------------------------------------------------------
# 游标：问题区 / RR
# ---------------------------------------------------------------------------

class WireCursor:
    """在单个 DNS 报文（AXFR 为单帧字节）上顺序推进的解析游标。

    游标只负责结构与边界：名称压缩、问题区四元组、RR 固定头与 RDATA
    边界；类型是否受支持、RRset 规则等语义由调用方在拿到
    :class:`RRView` 后自行判定，因此两个接口可以保持各自既有的检查
    顺序与错误优先级。
    """

    def __init__(self, buf: bytes, truncated_code: str):
        self.buf = buf
        self.truncated_code = truncated_code
        self.pos = HEADER_SIZE

    # -- 基础 -----------------------------------------------------------

    def truncated(self, message: str) -> ReviewError:
        return ReviewError(self.truncated_code, message, 422)

    def name(self, offset: int, where: str) -> ParsedName:
        """在任意偏移读取名称（用于 RDATA 内部名称，不改游标位置）。"""
        return read_name(
            self.buf, offset, where, truncated_code=self.truncated_code
        )

    def read_question(
        self, name_where: str, truncated_detail: str
    ) -> Question:
        """消费一个问题项（QNAME + QTYPE + QCLASS）。

        ``name_where`` 为名称错误定位前缀，``truncated_detail`` 为
        QTYPE/QCLASS 截断时的完整文案（两端索引措辞不同故整体传入）。
        """
        parsed = self.name(self.pos, name_where)
        self.pos = parsed.next_offset
        if self.pos + 4 > len(self.buf):
            raise self.truncated(truncated_detail)
        qtype, qclass = struct.unpack("!HH", self.buf[self.pos : self.pos + 4])
        self.pos += 4
        return Question(qname=parsed.name, qtype=qtype, qclass=qclass)

    def open_rr(self, name_where: str, head_detail: str) -> RRView:
        """消费一条 RR 的 owner 与 10 字节固定头，打开 RDATA 区间。

        返回的边界全部指向**原始报文字节**（不复制、不改写）：TSIG
        据此按原边界移除整条 TSIG RR 生成 HMAC 输入。此处**不做**
        TTL 范围与 RDATA 越界检查——调用方按各自既有的检查时机调用
        :meth:`check_ttl` 与 :meth:`require_rdata`（AXFR 必须先判定
        类型支持再查 TTL）。

        - ``name_where``：owner 名称的定位前缀；
        - ``head_detail``：10 字节固定头截断时的完整文案。
        """
        start = self.pos
        owner = self.name(self.pos, name_where)
        self.pos = owner.next_offset
        if self.pos + RECORD_FIXED_SIZE > len(self.buf):
            raise self.truncated(head_detail)
        rtype, rclass, ttl, rdlength = struct.unpack(
            "!HHIH",
            self.buf[self.pos : self.pos + RECORD_FIXED_SIZE],
        )
        self.pos += RECORD_FIXED_SIZE
        rdata_start = self.pos
        rdata_end = rdata_start + rdlength
        self.pos = rdata_end  # 越界时由 require_rdata 在下一时机报告
        return RRView(
            owner=owner.name,
            rtype=rtype,
            rclass=rclass,
            ttl=ttl,
            rdlength=rdlength,
            start=start,
            rdata_start=rdata_start,
            rdata_end=rdata_end,
        )

    def check_ttl(self, rr: RRView, where: str) -> None:
        """校验 31 位 TTL 上限（``invalid_record``）。"""
        if rr.ttl > MAX_TTL:
            raise ReviewError(
                "invalid_record",
                f"{where}：TTL {rr.ttl} 超出 31 位范围",
                422,
            )

    def require_rdata(self, rr: RRView, where: str) -> None:
        """确认 RDATA 区间未越过报文末尾（截断错误）。"""
        if rr.rdata_end > len(self.buf):
            raise self.truncated(f"{where}：RDATA 超出报文末尾")

    def at_end(self) -> bool:
        return self.pos == len(self.buf)

    def trailing_count(self) -> int:
        return len(self.buf) - self.pos
