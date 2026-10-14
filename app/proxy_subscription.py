"""Parse the VLESS WebSocket/TLS subscriptions used by EdgeTunnel.

Subscription contents are data, never executable Xray configuration. Only the
fields below are translated; TLS verification is always enabled.
"""
import base64
import hashlib
import ipaddress
import json
import re
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

MAX_SUBSCRIPTION_BYTES = 4 * 1024 * 1024
MAX_NODES = 512


class SubscriptionError(ValueError):
    pass


def public_hostname(value: str) -> str:
    value = str(value or "").strip().rstrip(".")
    if not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise SubscriptionError("节点地址无效。")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            value = value.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise SubscriptionError("节点域名无效。") from None
        if (len(value) > 253 or "." not in value
                or value.endswith((".localhost", ".local", ".internal"))
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
                       for p in value.split("."))):
            raise SubscriptionError("请使用公网节点地址。")
        return value
    if not address.is_global:
        raise SubscriptionError("订阅节点必须使用公网地址。")
    return str(address)


def subscription_url(value: str) -> str:
    value = str(value or "").strip()
    if len(value) > 8192 or any(ord(c) < 32 for c in value):
        raise SubscriptionError("订阅链接无效。")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise SubscriptionError("订阅链接无效。") from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment or port == 0):
        raise SubscriptionError("请输入不含用户名、密码和片段的 HTTPS 订阅链接。")
    public_hostname(parsed.hostname)
    return value


def parse_subscription(content: bytes) -> tuple[list[dict], int]:
    if not content or len(content) > MAX_SUBSCRIPTION_BYTES:
        raise SubscriptionError("订阅内容为空或超过 4 MiB。")
    try:
        text = content.decode("utf-8-sig").strip()
        if "://" not in text:
            compact = "".join(text.split())
            text = base64.b64decode(compact + "=" * (-len(compact) % 4),
                                    altchars=b"-_", validate=True).decode("utf-8-sig")
    except (ValueError, UnicodeError):
        raise SubscriptionError("订阅必须是 VLESS 链接列表或其 Base64 编码。") from None
    nodes, seen, skipped = [], set(), 0
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            node = parse_node(raw)
        except (SubscriptionError, ValueError, TypeError):
            skipped += 1
            continue
        if node["id"] in seen:
            continue
        seen.add(node["id"])
        nodes.append(node)
        if len(nodes) > MAX_NODES:
            raise SubscriptionError(f"订阅最多支持 {MAX_NODES} 个不同节点，请先精简订阅。")
    if not nodes:
        raise SubscriptionError("未找到支持的节点：请提供 VLESS + WebSocket + TLS 订阅。")
    return nodes, skipped


def parse_node(uri: str) -> dict:
    if len(uri) > 16384:
        raise SubscriptionError("节点链接过长。")
    parsed = urlsplit(uri)
    if parsed.scheme != "vless" or not parsed.hostname or not parsed.username or parsed.password:
        raise SubscriptionError("不支持的节点类型。")
    address = public_hostname(parsed.hostname)
    port = parsed.port or 443
    if not 1 <= port <= 65535:
        raise SubscriptionError("节点端口无效。")
    user_id = str(uuid.UUID(unquote(parsed.username)))
    values = parse_qs(parsed.query, keep_blank_values=True)
    if any(len(v) != 1 for v in values.values()):
        raise SubscriptionError("节点参数重复。")
    q = {k: v[0] for k, v in values.items()}
    if q.get("type", "tcp") != "ws" or q.get("security") != "tls":
        raise SubscriptionError("目前支持 VLESS + WebSocket + TLS。")
    if q.get("allowInsecure", q.get("insecure", "0")).lower() not in ("", "0", "false"):
        raise SubscriptionError("不接受跳过证书验证的节点。")
    if q.get("encryption", "none") != "none" or q.get("flow"):
        raise SubscriptionError("不支持此 VLESS 加密或流控参数。")
    sni = public_hostname(q.get("sni") or q.get("host") or address)
    host = public_hostname(q.get("host") or sni)
    path = q.get("path") or "/"
    if not path.startswith("/") or len(path) > 4096 or any(ord(c) < 32 for c in path):
        raise SubscriptionError("WebSocket 路径无效。")
    fingerprint = q.get("fp") or "chrome"
    if fingerprint not in {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}:
        raise SubscriptionError("不支持此 TLS 指纹。")
    tls = {"serverName": sni, "allowInsecure": False, "fingerprint": fingerprint,
           "alpn": ["http/1.1"]}
    ech = q.get("ech", "")
    if ech:
        if "+" in ech:
            ech_host, resolver = ech.split("+", 1)
            public_hostname(ech_host)
            subscription_url(resolver)
        elif not re.fullmatch(r"[A-Za-z0-9+/=_-]{1,16384}", ech):
            raise SubscriptionError("ECH 参数无效。")
        tls["echConfigList"] = ech
    outbound = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": address, "port": port,
                                  "users": [{"id": user_id, "encryption": "none"}]}]},
        "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": tls,
                           "wsSettings": {"path": path, "headers": {"Host": host}}},
    }
    identity = hashlib.sha256(json.dumps(outbound, sort_keys=True).encode()).hexdigest()[:20]
    name = "".join(c for c in unquote(parsed.fragment) if ord(c) >= 32)[:160] or address
    return {"id": identity, "name": name, "outbound": outbound}
