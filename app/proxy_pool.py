"""Request-scoped subscription proxies, with independent loopback Xray cores.

No system proxy, production Xray configuration, or Google credential is changed.
Refresh/check is an explicit admin operation; there is no periodic node sweep.
"""
import asyncio
import contextvars
import copy
import inspect
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from urllib.parse import urljoin, urlsplit

import httpx
from fastapi.responses import JSONResponse, StreamingResponse

from proxy_subscription import (
    MAX_SUBSCRIPTION_BYTES, SubscriptionError, parse_subscription, subscription_url,
)

_request_lease = contextvars.ContextVar("upstream_proxy_lease", default=None)


def current_proxy_url():
    lease = _request_lease.get()
    return lease.proxy_url if lease else None


def register_request_cleanup(callback):
    lease = _request_lease.get()
    if lease is not None:
        lease.cleanups.append(callback)


def exit_groups(nodes):
    """Anycast exits can alternate within a network even for distinct nodes.

    Rotate networks first, then rotate nodes within each network. This avoids
    concentrating adjacent requests on the fastest nodes of one Cloudflare PoP.
    Measurements are a routing hint, not a promise of a permanent external IP.
    """
    groups = {}
    for node in nodes:
        address = ipaddress.ip_address(node["exit_ip"])
        network = str(ipaddress.ip_network(f"{address}/{24 if address.version == 4 else 48}", strict=False))
        groups.setdefault(network, []).append(node)
    return groups


class PoolUnavailable(RuntimeError):
    pass


def _atomic_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".pool-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


async def _public_url(url):
    url = subscription_url(url)
    parsed = urlsplit(url)
    records = await asyncio.get_running_loop().getaddrinfo(
        parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    if not records or any(not ipaddress.ip_address(r[4][0]).is_global for r in records):
        raise SubscriptionError("订阅域名必须解析到公网地址。")
    return url


async def fetch_subscription(url):
    # Redirects are validated individually; secrets from the URL are never logged.
    async with httpx.AsyncClient(trust_env=False, timeout=30, follow_redirects=False,
                                 headers={"User-Agent": "v2rayN/vertex2openai-proxy-pool"}) as client:
        for _ in range(4):
            url = await _public_url(url)
            async with client.stream("GET", url) as response:
                if response.is_redirect:
                    url = urljoin(url, response.headers.get("location", ""))
                    continue
                if response.status_code != 200:
                    raise SubscriptionError(f"订阅服务器返回 HTTP {response.status_code}。")
                data = bytearray()
                async for part in response.aiter_bytes():
                    data.extend(part)
                    if len(data) > MAX_SUBSCRIPTION_BYTES:
                        raise SubscriptionError("订阅内容超过 4 MiB。")
                return bytes(data)
    raise SubscriptionError("订阅重定向次数过多。")


class XrayGeneration:
    def __init__(self, directory, nodes):
        self.directory = Path(directory)
        self.nodes = copy.deepcopy(nodes)
        self.process = None
        self.config_path = self.directory / ("core-" + uuid.uuid4().hex + ".json")
        self.references = 0
        self.retired = False
        self._closed = False

    async def start(self):
        binary = os.environ.get("XRAY_BINARY") or shutil.which("xray") or "/usr/local/bin/xray"
        if not Path(binary).is_file():
            raise PoolUnavailable("未找到 Xray，请先安装 Xray 并设置 XRAY_BINARY。")
        reservations = []
        user, password = uuid.uuid4().hex, uuid.uuid4().hex
        config = {"log": {"loglevel": "none"}, "inbounds": [],
                  "outbounds": [{"tag": "blocked", "protocol": "blackhole"}],
                  "routing": {"rules": []}}
        try:
            for index, node in enumerate(self.nodes):
                sock = socket.socket()
                sock.bind(("127.0.0.1", 0))
                reservations.append(sock)
                port = sock.getsockname()[1]
                node["proxy_url"] = f"http://{user}:{password}@127.0.0.1:{port}"
                tag = f"node-{index}"
                config["inbounds"].append({"tag": tag, "listen": "127.0.0.1", "port": port,
                    "protocol": "http", "settings": {"accounts": [{"user": user, "pass": password}]}})
                outbound = copy.deepcopy(node["outbound"])
                outbound["tag"] = tag
                config["outbounds"].append(outbound)
                config["routing"]["rules"].append({"type": "field", "inboundTag": [tag], "outboundTag": tag})
            _atomic_json(self.config_path, config)
            for sock in reservations:
                sock.close()
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            self.process = subprocess.Popen([binary, "run", "-config", str(self.config_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=flags)
            ports = [urlsplit(self.nodes[i]["proxy_url"]).port for i in {0, len(self.nodes) - 1}]
            for _ in range(100):
                if self.process.poll() is not None:
                    raise PoolUnavailable("Xray 代理核心启动失败，请检查版本与节点参数。")
                try:
                    for port in ports:
                        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 0.2)
                        writer.close()
                        await writer.wait_closed()
                    return
                except (OSError, asyncio.TimeoutError):
                    await asyncio.sleep(0.1)
            raise PoolUnavailable("Xray 代理核心启动超时。")
        except BaseException:
            await self.close()
            raise
        finally:
            for sock in reservations:
                sock.close()

    def alive(self):
        return self.process is not None and self.process.poll() is None and not self._closed

    async def close(self):
        if self._closed:
            return
        self._closed = True
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                await asyncio.to_thread(self.process.wait, timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                await asyncio.to_thread(self.process.wait, timeout=5)
        self.config_path.unlink(missing_ok=True)


class ProxyLease:
    def __init__(self, manager, generation=None, node=None):
        self.manager, self.generation, self.node = manager, generation, node
        self.proxy_url = node.get("proxy_url") if node else None
        self.cleanups = []
        self.released = False
        self._release_task = None

    async def release(self):
        if self._release_task is None:
            self.released = True
            self._release_task = asyncio.create_task(self._finish_release())
            self.manager.cleanup_tasks.add(self._release_task)
            self._release_task.add_done_callback(self.manager.cleanup_tasks.discard)
        # A cancelled SSE consumer must not cancel client/core cleanup with it.
        await asyncio.shield(self._release_task)

    async def _finish_release(self):
        for callback in reversed(self.cleanups):
            try:
                result = callback()
                if inspect.isawaitable(result):
                    await result
            except Exception:
                pass
        if self.generation:
            async with self.manager.lock:
                self.generation.references -= 1
                await self.manager._reap()


class LeasedStreamingResponse(StreamingResponse):
    def __init__(self, original, lease):
        self.lease = lease
        iterator = original.body_iterator

        async def chunks():
            token = _request_lease.set(lease)
            try:
                async for chunk in iterator:
                    yield chunk
            finally:
                try:
                    if hasattr(iterator, "aclose"):
                        await iterator.aclose()
                finally:
                    _request_lease.reset(token)
                    await lease.release()

        super().__init__(chunks(), status_code=original.status_code,
                         media_type=original.media_type, background=original.background)
        self.raw_headers = list(original.raw_headers)

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            # Also releases when the browser disconnects before iteration starts.
            await self.lease.release()


class ProxyPool:
    def __init__(self, directory=None, generation_factory=XrayGeneration):
        self.directory = Path(directory or os.path.join(os.environ.get("STATE_DIR", "."), "proxy_pool"))
        self.state_file = self.directory / "state.json"
        self.lock = asyncio.Lock()
        self.generation_factory = generation_factory
        self.config = {"enabled": False, "subscription_url": "", "name_filter": ""}
        self.generation = None
        self.retired = []
        self.cursor = 0
        self.group_cursors = {}
        self.task = None
        self.last_error = ""
        self.job = {"state": "idle", "checked": 0, "total": 0, "passed": 0}
        self.last_updated = None
        self.imported = 0
        self.skipped = 0
        self.last_selected = None
        self.selections = 0
        self.cleanup_tasks = set()

    async def startup(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.state_file.exists():
            return
        try:
            saved = json.loads(self.state_file.read_text(encoding="utf-8"))
            self.config = saved["config"]
            self.last_updated = saved.get("updated_at")
            self.imported, self.skipped = saved.get("imported", 0), saved.get("skipped", 0)
            if self.config.get("enabled"):
                nodes = saved.get("nodes", [])
                if not nodes:
                    raise PoolUnavailable("代理池已启用但没有已检测节点，请更新订阅。")
                generation = self.generation_factory(self.directory, nodes)
                await generation.start()
                self.generation = generation
        except Exception as exc:
            self.last_error = self._safe_error(exc)
            print("⚠️ [代理池] " + self.last_error)

    @staticmethod
    def _safe_error(exc):
        if isinstance(exc, (SubscriptionError, PoolUnavailable)):
            return str(exc)
        return f"操作失败（{type(exc).__name__}），请检查订阅和网络后重试。"

    def status(self):
        nodes = self.generation.nodes if self.generation else []
        return {"enabled": bool(self.config.get("enabled")),
                "subscription_configured": bool(self.config.get("subscription_url")),
                "name_filter": self.config.get("name_filter", ""),
                "ready": bool(self.generation and self.generation.alive() and nodes),
                "node_count": len(nodes), "distinct_exit_ips": len({n.get("exit_ip") for n in nodes if n.get("exit_ip")}),
                "exit_network_count": len(exit_groups(nodes)), "rotation_strategy": "network_round_robin",
                "imported_count": self.imported, "skipped_count": self.skipped,
                "last_updated": self.last_updated, "last_error": self.last_error,
                "job": dict(self.job), "selections": self.selections,
                "last_selected": self.last_selected, "automatic_checks": False,
                "nodes": [{k: n.get(k) for k in ("id", "name", "exit_ip", "latency_ms", "checked_at")} for n in nodes]}

    def _save(self, config, nodes, updated_at, imported, skipped):
        clean = [{k: v for k, v in n.items() if k != "proxy_url"} for n in nodes]
        _atomic_json(self.state_file, {"config": config, "nodes": clean, "updated_at": updated_at,
                                      "imported": imported, "skipped": skipped})

    async def configure(self, enabled, url="", name_filter="", refresh=False):
        async with self.lock:
            if self.task and not self.task.done():
                raise PoolUnavailable("已有更新检测正在进行，请等待完成。")
            if len(self.retired) >= 2:
                raise PoolUnavailable("旧出口仍有请求未结束，请稍后再更新订阅。")
            chosen_url = subscription_url(url) if url.strip() else self.config.get("subscription_url", "")
            name_filter = str(name_filter or "").strip()
            if len(name_filter) > 500:
                raise SubscriptionError("节点筛选条件最多 500 个字符。")
            if enabled and not chosen_url:
                raise SubscriptionError("请先填写订阅链接。")
            proposed = {"enabled": bool(enabled), "subscription_url": chosen_url, "name_filter": name_filter}
            if not enabled and not refresh:
                nodes = self.generation.nodes if self.generation else self._cached_nodes()
                self._save(proposed, nodes, self.last_updated, self.imported, self.skipped)
                self.config = proposed
                if self.generation:
                    self.generation.retired = True
                    self.retired.append(self.generation)
                    self.generation = None
                await self._reap()
                self.last_error = ""
                return self.status()
            if not chosen_url:
                raise SubscriptionError("请先填写订阅链接。")
            self.job = {"state": "downloading", "checked": 0, "total": 0, "passed": 0}
            self.last_error = ""
            self.task = asyncio.create_task(self._refresh(proposed))
            return self.status()

    def _cached_nodes(self):
        if not self.state_file.exists():
            return []
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8")).get("nodes", [])
        except (ValueError, OSError):
            return []

    async def _check_node(self, node):
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(proxy=node["proxy_url"], trust_env=False,
                    timeout=httpx.Timeout(12.0), follow_redirects=False) as client:
                response = await client.get("https://checkip.amazonaws.com/")
                response.raise_for_status()
                exit_ip = ipaddress.ip_address(response.text.strip())
                if not exit_ip.is_global:
                    return None
                # No API keys, Cookies, model generation, or Google quota are used.
                response = await client.get("https://www.gstatic.com/generate_204")
                if response.status_code != 204:
                    return None
                return {**node, "exit_ip": str(exit_ip), "checked_at": time.time(),
                        "latency_ms": round((time.monotonic() - started) * 1000)}
        except Exception:
            return None

    async def _refresh(self, proposed):
        candidate = None
        try:
            content = await fetch_subscription(proposed["subscription_url"])
            nodes, skipped = parse_subscription(content)
            imported = len(nodes)
            terms = [x.strip().casefold() for x in proposed["name_filter"].replace("，", ",").split(",") if x.strip()]
            if terms:
                nodes = [n for n in nodes if any(t in n["name"].casefold() for t in terms)]
            if not nodes:
                raise SubscriptionError("筛选后没有节点，请调整节点名称关键词。")
            candidate = self.generation_factory(self.directory, nodes)
            await candidate.start()
            self.job.update(state="checking", total=len(nodes))
            semaphore = asyncio.Semaphore(6)

            async def check(node):
                async with semaphore:
                    result = await self._check_node(node)
                    self.job["checked"] += 1
                    self.job["passed"] += bool(result)
                    return result

            results = await asyncio.gather(*(check(n) for n in candidate.nodes))
            # Different subscription entries may have the same real exit.
            unique = {}
            for node in sorted((n for n in results if n), key=lambda n: n["latency_ms"]):
                unique.setdefault(node["exit_ip"], node)
            selected = list(unique.values())
            if len(selected) < 2:
                raise PoolUnavailable("至少需要两个不同的可用出口；本次更新未替换原代理池。")
            candidate.nodes = selected
            async with self.lock:
                updated_at = time.time()
                self._save(proposed, selected, updated_at, imported, skipped)
                previous = self.generation
                self.generation = candidate if proposed["enabled"] else None
                self.config = proposed
                self.last_updated, self.imported, self.skipped = updated_at, imported, skipped
                self.cursor = 0
                self.group_cursors = {}
                self.last_selected = None
                if previous:
                    previous.retired = True
                    self.retired.append(previous)
                if not proposed["enabled"]:
                    await candidate.close()
                candidate = None
                await self._reap()
                self.job.update(state="complete", unique_exits=len(selected))
                print(f"✅ [代理池] 更新完成：{imported} 个订阅节点，{len(selected)} 个不同的可用出口。")
        except asyncio.CancelledError:
            self.job["state"] = "cancelled"
            raise
        except Exception as exc:
            self.last_error = self._safe_error(exc)
            self.job["state"] = "failed"
            print("⚠️ [代理池] " + self.last_error)
        finally:
            if candidate:
                await candidate.close()

    async def _reap(self):
        for generation in list(self.retired):
            if not generation.references:
                await generation.close()
                self.retired.remove(generation)

    async def acquire(self):
        async with self.lock:
            if not self.config.get("enabled"):
                return ProxyLease(self)
            generation = self.generation
            if not generation or not generation.alive() or not generation.nodes:
                raise PoolUnavailable("代理池已启用但不可用，请在后台更新检测或关闭代理池。")
            groups = exit_groups(generation.nodes)
            network = list(groups)[self.cursor % len(groups)]
            members = groups[network]
            index = self.group_cursors.get(network, 0)
            node = members[index % len(members)]
            self.group_cursors[network] = index + 1
            self.cursor += 1
            self.selections += 1
            generation.references += 1
            self.last_selected = {k: node.get(k) for k in ("id", "name", "exit_ip")}
            print(f"🌐 [代理轮换] {node['name']} · 检测出口 {node.get('exit_ip', '未知')}")
            return ProxyLease(self, generation, node)

    async def call(self, callback):
        try:
            lease = await self.acquire()
        except PoolUnavailable as exc:
            return JSONResponse(status_code=503, content={"error": {"message": str(exc),
                                "type": "proxy_pool_unavailable", "code": 503}})
        token = _request_lease.set(lease)
        try:
            response = await callback()
            if isinstance(response, StreamingResponse):
                response = LeasedStreamingResponse(response, lease)
            else:
                await lease.release()
            if lease.node:
                response.headers["X-Proxy-Node"] = lease.node["id"]
                response.headers["X-Proxy-Exit-IP"] = lease.node.get("exit_ip", "unknown")
            return response
        except BaseException:
            await lease.release()
            raise
        finally:
            _request_lease.reset(token)

    async def check_next(self):
        if not self.config.get("enabled"):
            return JSONResponse({"error": "请先启用代理池。"}, status_code=400)

        async def check():
            lease = _request_lease.get()
            result = await self._check_node(lease.node)
            if not result:
                return JSONResponse({"error": "本次出口检测失败，可测试下一出口或重新更新订阅。"}, status_code=502)
            return JSONResponse({"node": result["name"], "observed_exit_ip": result["exit_ip"],
                                 "latency_ms": result["latency_ms"], "google_connectivity": True})

        return await self.call(check)

    async def shutdown(self):
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        if self.cleanup_tasks:
            await asyncio.gather(*list(self.cleanup_tasks), return_exceptions=True)
        generations = self.retired + ([self.generation] if self.generation else [])
        for generation in generations:
            await generation.close()
        self.generation = None
        self.retired = []


proxy_pool = ProxyPool()
