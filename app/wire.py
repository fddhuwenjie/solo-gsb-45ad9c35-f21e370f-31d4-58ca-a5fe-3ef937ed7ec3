"""DNS wire 报文的共享遍历层（RFC 1035 §4）。

:mod:`app.axfr`（逐帧解析 TCP AXFR 响应流）与 :mod:`app.tsig`
（校验单个携带 TSIG 的报文）共用同一套底层逻辑：

- :class:`WireReader` 持有报文字节与一个单调推进的偏移游标；
- :meth:`WireReader.read_name` 实现名称解压（RFC 1035 §4.1.4），
  owner 与 RDATA 内的压缩指针均可指向报文任意已出现位置，返回
  **规范名称**（小写绝对名）与**消费后的偏移**（指针只占 2 字节）；
- :meth:`WireReader.read_question` 是问题区游标，返回规范问题并推进；
- :meth:`WireReader.read_rr` 是 RR 游标，只切出**原始 RR 边界**
  （owner、TYPE/CLASS/TTL/RDLENGTH、RDATA 起止与整条 RR 结束偏移），
  不解释 RDATA、不做任何类型/TTL 判定——各区仍按什么顺序检查哪些
  字段完全由调用方保持。

两个入口的错误码不同（AXFR 的截断码是 ``frame_truncated``，TSIG 是
``message_truncated``），因此截断码在打开游标时注入；压缩指针成环
（``compression_pointer_loop``）、越界
（``compression_pointer_out_of_bounds``）与非法名称
（``invalid_name``）两接口共用同一错误码与同一套定位文案；RDATA 越界、
记录头截断等定位文案由调用方传入，保持各接口原有的措辞。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .review import ReviewError
from .zoneparse import ZoneParseError, validate_name

# 与区域文本解析一致的 31 位 TTL 上限
MAX_TTL = 2**31 - 1


@dataclass(frozen=True)
class WireQuestion:
    """问题区一项：规范（小写绝对）qname 与 TYPE/CLASS。"""

    qname: str
    qtype: int
    qclass: int

    def as_tuple(self) -> tuple:
        return (self.qname, self.qtype, self.qclass)


@dataclass(frozen=True)
class RawRR:
    """RR 游标切出的原始边界：字段值是快照，边界全部基于原报文字节。

    ``start`` 为 owner 起始偏移，``rdata_start``/``rdata_end`` 圈定
    原报文中的 RDATA 字节，``end`` 为整条 RR（含 RDLENGTH 字节）之后
    的下一偏移。TSIG 生成 HMAC 输入时按 ``start`` 截断即可得到原报文
    字节边界；RDATA 内容仍在原报文 ``data`` 上按需解释。
    """

    start: int
    rdata_start: int
    rdata_end: int
    rtype: int
    rclass: int
    ttl: int
    rdlength: int
    owner: str

    @property
    def end(self) -> int:
        return self.rdata_end


class WireReader:
    """单个 DNS 报文上的偏移游标（问题区 / RR 共用）。"""

    def __init__(self, data: bytes, truncated_code: str, pos: int = 12):
        self.data = data
        self.pos = pos
        self._truncated_code = truncated_code

    @classmethod
    def open(cls, data: bytes, truncated_code: str, header_detail: str):
        """校验 12 字节 DNS 头并返回游标与解出头字段。

        ``header_detail`` 是头不足 12 字节时的完整定位文案（各接口
        原有措辞不同，由调用方提供）。
        """
        if len(data) < 12:
            raise ReviewError(
                truncated_code,
                f"{header_detail}（实际 {len(data)} 字节）",
                422,
            )
        (
            message_id,
            flags,
            qdcount,
            ancount,
            nscount,
            arcount,
        ) = struct.unpack("!HHHHHH", data[:12])
        reader = cls(data, truncated_code)
        return reader, {
            "id": message_id,
            "flags": flags,
            "qdcount": qdcount,
            "ancount": ancount,
            "nscount": nscount,
            "arcount": arcount,
        }

    def truncated(self, detail: str) -> ReviewError:
        return ReviewError(self._truncated_code, detail, 422)

    # ------------------------------------------------------------------
    # 名称解压（RFC 1035 §4.1.4）
    # ------------------------------------------------------------------

    def read_name(self, offset: int, where: str) -> tuple[str, int]:
        """在 ``offset`` 处读取一个（可压缩的）域名。

        返回 ``(小写绝对名, 名称结束后下一偏移)``：名称以压缩指针结束
        时，下一偏移是该指针 2 字节之后，而不是指针目标处；指针成环/
        越界、报文截断、名称非法均按调用方的错误码抛 422。
        """
        data = self.data
        labels: list[str] = []
        pos = offset
        end: int | None = None  # 首次跟随压缩指针后确定的“下一偏移”
        visited: set[int] = set()  # 已跳转过的指针目标（环检测）
        while True:
            if pos >= len(data):
                raise self.truncated(f"{where}：名称超出报文末尾")
            length = data[pos]
            if length & 0xC0 == 0xC0:
                if pos + 1 >= len(data):
                    raise self.truncated(
                        f"{where}：压缩指针只有半个字节"
                    )
                target = ((length & 0x3F) << 8) | data[pos + 1]
                if target >= len(data):
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
            if pos + length > len(data):
                raise self.truncated(f"{where}：标签超出报文末尾")
            raw = data[pos : pos + length]
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
        return name, (end if end is not None else pos)

    # ------------------------------------------------------------------
    # 问题区游标
    # ------------------------------------------------------------------

    def read_question(self, where: str, truncated_detail: str) -> WireQuestion:
        """读取一项 QNAME/QTYPE/QCLASS，并把游标推进到该项之后。"""
        qname, self.pos = self.read_name(self.pos, where)
        if self.pos + 4 > len(self.data):
            raise self.truncated(truncated_detail)
        qtype, qclass = struct.unpack(
            "!HH", self.data[self.pos : self.pos + 4]
        )
        self.pos += 4
        return WireQuestion(qname=qname, qtype=qtype, qclass=qclass)

    # ------------------------------------------------------------------
    # RR 游标
    # ------------------------------------------------------------------

    def read_rr(self, where: str, header_detail: str) -> RawRR:
        """切出一条 RR 的原始边界，并把游标推进到该 RR 之后。

        只解析 owner 与固定 10 字节记录头；不校验 TYPE/TTL，也不检查
        RDATA 是否越界——两者的检查顺序与错误文案属于各接口语义，由
        调用方在拿到边界后自行完成（可用 :meth:`require_rdata_within`
        与 ``RawRR.rdata_start`` 在原报文上解释 RDATA）。
        """
        start = self.pos
        owner, self.pos = self.read_name(self.pos, where)
        if self.pos + 10 > len(self.data):
            raise self.truncated(header_detail)
        rtype, rclass, ttl, rdlength = struct.unpack(
            "!HHIH", self.data[self.pos : self.pos + 10]
        )
        rdata_start = self.pos + 10
        rdata_end = rdata_start + rdlength
        self.pos = rdata_end
        return RawRR(
            start=start,
            rdata_start=rdata_start,
            rdata_end=rdata_end,
            rtype=rtype,
            rclass=rclass,
            ttl=ttl,
            rdlength=rdlength,
            owner=owner,
        )

    def require_rdata_within(self, rr: RawRR, detail: str) -> None:
        """检查 RR 的 RDATA 边界未越过报文末尾（原报文字节边界）。"""
        if rr.rdata_end > len(self.data):
            raise self.truncated(detail)

    def require_end(self, code: str, detail: str) -> None:
        """检查各区游标恰好消费到报文末尾（尾随字节检测）。

        错误码与定位文案由调用方给出（AXFR 不检查尾随字节：授权区/
        附加区本就跳过）。
        """
        if self.pos != len(self.data):
            raise ReviewError(
                code,
                f"{detail}仍有 {len(self.data) - self.pos} 个尾随字节",
                422,
            )
