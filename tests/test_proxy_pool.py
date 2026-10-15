import asyncio
import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch
from types import SimpleNamespace
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
os.environ.setdefault("API_KEY", "proxy-pool-offline-test-key")

from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.testclient import TestClient
import httpx

from proxy_subscription import MAX_NODES, parse_subscription, parse_node, SubscriptionError, subscription_url
from proxy_pool import ProxyPool, current_proxy_url, register_request_cleanup

TEST_UUID = "00000000-0000-4000-8000-000000000001"
SECRET_URL = "https://subscription.example.com/sub?token=do-not-expose"


def node_uri(host="1.1.1.1", name="Test", **kwargs):
    q = {"security": "tls", "type": "ws", "host": "edge.example.com", "sni": "edge.example.com",
         "path": "/?proxyip=" + host + ":443", "ech": "cloudflare-ech.com+https://dns.alidns.com/dns-query"}
    q.update(kwargs)
    return f"vless://{TEST_UUID}@{host}:443?{urlencode(q)}#{name}"


def checked_node(host, exit_ip):
    return {**parse_node(node_uri(host)), "exit_ip": exit_ip, "latency_ms": 30, "checked_at": 1}


class FakeGeneration:
    def __init__(self, directory, nodes):
        self.nodes = copy.deepcopy(nodes)
        self.references = 0
        self.retired = False
        self.closed = False
        self.started = False

    async def start(self):
        for i, node in enumerate(self.nodes):
            node["proxy_url"] = f"http://test:secret@127.0.0.1:{20000+i}"
        self.started = True

    def alive(self):
        return self.started and not self.closed

    async def close(self):
        self.closed = True


class SubscriptionTests(unittest.TestCase):
    def test_preserves_tls_ech_and_pinned_path(self):
        node = parse_node(node_uri())
        stream = node["outbound"]["streamSettings"]
        self.assertFalse(stream["tlsSettings"]["allowInsecure"])
        self.assertEqual(stream["tlsSettings"]["echConfigList"], "cloudflare-ech.com+https://dns.alidns.com/dns-query")
        self.assertEqual(stream["wsSettings"]["path"], "/?proxyip=1.1.1.1:443")

    def test_raw_and_base64_subscriptions_deduplicate(self):
        raw = (node_uri() + "\n" + node_uri(name="Duplicate") + "\n" + node_uri("8.8.8.8") + "\ntrojan://unsupported").encode()
        for content in (raw, base64.b64encode(raw), base64.urlsafe_b64encode(raw).rstrip(b"=")):
            nodes, skipped = parse_subscription(content)
            self.assertEqual(len(nodes), 2)
            self.assertEqual(skipped, 1)

    def test_rejects_unverified_tls_and_private_destinations(self):
        for uri in (node_uri(allowInsecure="1"), node_uri("127.0.0.1"), node_uri("169.254.169.254"),
                    node_uri("10.0.0.1"), node_uri(type="grpc"), node_uri(security="none")):
            with self.subTest(uri=uri), self.assertRaises(SubscriptionError):
                parse_subscription(uri.encode())

    def test_imports_expanded_587_node_subscription(self):
        raw = "\n".join(node_uri(f"104.28.{i // 250}.{i % 250 + 1}") for i in range(587)).encode()
        for content in (raw, base64.b64encode(raw)):
            nodes, skipped = parse_subscription(content)
            self.assertEqual(len(nodes), 587)
            self.assertEqual(skipped, 0)

    def test_rejects_subscription_over_node_limit(self):
        raw = "\n".join(node_uri(f"104.28.{i // 250}.{i % 250 + 1}") for i in range(MAX_NODES + 1)).encode()
        with self.assertRaises(SubscriptionError):
            parse_subscription(raw)

    def test_invalid_subscription_links(self):
        for url in ("file:///etc/passwd", "http://example.com/sub", "https://localhost/sub",
                    "https://127.0.0.1/sub", "https://user:pass@example.com/sub", "https://example.com/#token"):
            with self.subTest(url=url), self.assertRaises(SubscriptionError):
                subscription_url(url)

    def test_invalid_and_empty_payload(self):
        for content in (b"", b"not-a-subscription", b"<html>Login</html>", b"x" * (4*1024*1024+1)):
            with self.assertRaises(SubscriptionError):
                parse_subscription(content)


class PoolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pool = ProxyPool(self.tmp.name, FakeGeneration)
        self.pool.config = {"enabled": True, "subscription_url": SECRET_URL, "name_filter": ""}
        generation = FakeGeneration(self.tmp.name, [checked_node("1.1.1.1", "9.9.9.9"), checked_node("8.8.8.8", "8.8.4.4")])
        await generation.start()
        self.pool.generation = generation

    async def asyncTearDown(self):
        await self.pool.shutdown()
        self.tmp.cleanup()

    async def test_round_robin_with_concurrent_requests_and_context_isolation(self):
        async def request():
            async def upstream():
                before = current_proxy_url()
                await asyncio.sleep(0.001)
                self.assertEqual(before, current_proxy_url())
                return JSONResponse({"proxy": before})
            return await self.pool.call(upstream)
        responses = await asyncio.gather(*(request() for _ in range(20)))
        urls = [json.loads(r.body)["proxy"] for r in responses]
        self.assertEqual(urls[::2], [urls[0]]*10)
        self.assertEqual(urls[1::2], [urls[1]]*10)
        self.assertNotEqual(urls[0], urls[1])
        self.assertIsNone(current_proxy_url())
        self.assertEqual(self.pool.generation.references, 0)

    async def test_interleaves_networks_then_rotates_members_within_each_network(self):
        self.pool.generation.nodes = [
            {**checked_node("1.1.1.1", "104.28.165.174"), "proxy_url":"http://first"},
            {**checked_node("8.8.8.8", "104.28.165.175"), "proxy_url":"http://second"},
            {**checked_node("9.9.9.9", "104.28.211.98"), "proxy_url":"http://third"},
        ]
        selected = []
        for _ in range(4):
            lease = await self.pool.acquire()
            selected.append(lease.proxy_url)
            await lease.release()
        self.assertEqual(selected, ["http://first", "http://third", "http://second", "http://third"])
        self.assertEqual(self.pool.status()["exit_network_count"], 2)

    async def test_disabled_pool_keeps_original_connection_behavior(self):
        self.pool.config["enabled"] = False
        async def upstream():
            self.assertIsNone(current_proxy_url())
            return JSONResponse({"ok": True})
        result = await self.pool.call(upstream)
        self.assertEqual(result.status_code, 200)
        self.assertNotIn("X-Proxy-Node", result.headers)

    async def test_enabled_empty_pool_does_not_silently_go_direct(self):
        self.pool.generation = None
        upstream = AsyncMock()
        response = await self.pool.call(upstream)
        self.assertEqual(response.status_code, 503)
        upstream.assert_not_called()

    async def test_non_stream_response_releases_client_and_exposes_only_safe_headers(self):
        close = AsyncMock()
        async def upstream():
            register_request_cleanup(close)
            return JSONResponse({"error": "quota"}, status_code=429)
        response = await self.pool.call(upstream)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["X-Proxy-Exit-IP"], "9.9.9.9")
        close.assert_awaited_once()
        self.assertEqual(self.pool.generation.references, 0)

    async def test_refresh_preserves_old_stream_until_consumed_by_background_pump(self):
        old = self.pool.generation
        close = AsyncMock()
        async def upstream():
            expected = current_proxy_url()
            register_request_cleanup(close)
            async def chunks():
                for _ in range(2):
                    self.assertEqual(current_proxy_url(), expected)
                    await asyncio.sleep(0)
                    yield b"data: hello\n\n"
            return StreamingResponse(chunks(), media_type="text/event-stream")
        response = await self.pool.call(upstream)
        self.assertEqual(old.references, 1)
        with patch("proxy_pool.fetch_subscription", AsyncMock(return_value=(node_uri()+"\n"+node_uri("8.8.8.8")).encode())), \
             patch.object(self.pool, "_check_node", AsyncMock(side_effect=lambda n: {**n, "exit_ip": "9.9.9.9" if n["id"] == old.nodes[0]["id"] else "8.8.4.4", "latency_ms": 1})):
            await self.pool.configure(True, refresh=True)
            await self.pool.task
        self.assertEqual(self.pool.job["state"], "complete")
        self.assertFalse(old.closed)
        async def pump():
            return [x async for x in response.body_iterator]
        chunks = await asyncio.create_task(pump())
        self.assertEqual(len(chunks), 2)
        self.assertTrue(old.closed)
        close.assert_awaited_once()
        self.assertTrue(self.pool.generation.alive())

    async def test_disconnect_before_stream_iteration_releases_lease(self):
        async def upstream():
            async def chunks():
                yield b"never sent"
            return StreamingResponse(chunks())
        response = await self.pool.call(upstream)
        async def send(message):
            raise OSError("disconnected")
        async def receive():
            return {"type": "http.disconnect"}
        with self.assertRaises(Exception):
            await response({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send)
        self.assertEqual(self.pool.generation.references, 0)

    async def test_cancelled_upstream_cleans_up(self):
        async def upstream():
            raise asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            await self.pool.call(upstream)
        self.assertEqual(self.pool.generation.references, 0)

    async def test_failed_refresh_keeps_live_pool_and_redacts_network_errors(self):
        old = self.pool.generation
        with patch("proxy_pool.fetch_subscription", AsyncMock(side_effect=httpx.ConnectError(SECRET_URL))):
            await self.pool.configure(True, refresh=True)
            await self.pool.task
        self.assertIs(self.pool.generation, old)
        self.assertTrue(old.alive())
        self.assertEqual(self.pool.job["state"], "failed")
        self.assertNotIn("do-not-expose", json.dumps(self.pool.status()))

    async def test_exported_status_contains_no_subscription_or_proxy_credentials(self):
        status = json.dumps(self.pool.status())
        for value in (TEST_UUID, SECRET_URL, "test:secret", "outbound", "proxy_url"):
            self.assertNotIn(value, status)

    async def test_refresh_deduplicates_real_exit_and_restart_uses_cache_without_network(self):
        raw = "\n".join(node_uri(h) for h in ("1.1.1.1", "8.8.8.8", "9.9.9.9")).encode()
        async def check(node):
            host = node["outbound"]["settings"]["vnext"][0]["address"]
            return {**node, "exit_ip": "8.8.4.4" if host == "9.9.9.9" else "1.0.0.1", "latency_ms": 4}
        with patch("proxy_pool.fetch_subscription", AsyncMock(return_value=raw)), patch.object(self.pool, "_check_node", check):
            await self.pool.configure(True, refresh=True)
            await self.pool.task
        self.assertEqual(self.pool.status()["node_count"], 2)
        self.assertNotIn("proxy_url", self.pool.state_file.read_text())
        if os.name != "nt":
            self.assertEqual(self.pool.state_file.stat().st_mode & 0o777, 0o600)
        restored = ProxyPool(self.tmp.name, FakeGeneration)
        try:
            with patch("proxy_pool.fetch_subscription", AsyncMock(side_effect=AssertionError("unexpected network"))):
                await restored.startup()
            self.assertTrue(restored.status()["ready"])
            self.assertEqual(restored.status()["node_count"], 2)
        finally:
            await restored.shutdown()

    async def test_sdk_http_options_use_request_proxy_for_sync_and_async(self):
        import config
        from http_options import get_http_options
        async def upstream():
            with patch.object(config, "PROXY_URL", "http://old-proxy.example.com:8080"):
                options = get_http_options()
                self.assertEqual(options.client_args["proxy"], current_proxy_url())
                self.assertEqual(options.async_client_args["proxy"], current_proxy_url())
                self.assertFalse(options.async_client_args["trust_env"])
            return JSONResponse({"ok": True})
        await self.pool.call(upstream)

    async def test_cookie_channel_passes_each_selected_proxy_to_its_http_client(self):
        from models import OpenAIRequest
        from upstreams import cookie_proxy
        request = OpenAIRequest(model="gemini-3.6-flash", messages=[{"role":"user", "content":"offline test"}])
        fast_request = SimpleNamespace(is_disconnected=AsyncMock(return_value=False))
        captured = []
        def client_factory(**kwargs):
            captured.append(kwargs)
            client = AsyncMock()
            client.__aenter__.return_value = client
            client.post.return_value = httpx.Response(401, text="offline fixture")
            return client
        with patch.object(cookie_proxy, "_get_cookie_string", return_value="SAPISID=offline"), \
             patch.object(cookie_proxy, "_get_project_id", return_value="offline-project"), \
             patch.object(cookie_proxy, "build_headers", return_value={"Cookie":"SAPISID=offline"}), \
             patch.object(cookie_proxy, "build_batch_graphql_body_async", AsyncMock(return_value={"variables":{}})), \
             patch.object(cookie_proxy, "get_retry_settings", return_value=(0,0)), \
             patch.object(cookie_proxy.httpx, "AsyncClient", side_effect=client_factory):
            for _ in range(2):
                await self.pool.call(lambda: cookie_proxy.CookieProxyUpstream().chat_completions(request, fast_request))
        self.assertEqual(len(captured), 2)
        self.assertNotEqual(captured[0]["proxy"], captured[1]["proxy"])
        self.assertTrue(all(c["trust_env"] is False for c in captured))

    async def test_express_primary_and_fallback_share_proxy_and_close_after_stream(self):
        from models import OpenAIRequest
        from upstreams import express_sdk
        request = OpenAIRequest(model="gemini-3.6-flash", messages=[{"role":"user", "content":"offline test"}], stream=True)
        keys = Mock()
        keys.get_total_keys.return_value = 1
        keys.get_express_record.return_value = {"key":"offline-key", "project_id":"offline-project"}
        fast_request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(express_key_manager=keys)))
        clients, proxies = [], []
        def factory(**kwargs):
            proxies.append(kwargs["http_options"].async_client_args["proxy"])
            client = SimpleNamespace(aio=SimpleNamespace(aclose=AsyncMock()), close=Mock())
            clients.append(client)
            return client
        async def execute(*args, **kwargs):
            async def stream():
                kwargs["fallback_client_factory"]()
                yield b"data: offline fixture\n\n"
            return StreamingResponse(stream())
        with patch.object(express_sdk.genai, "Client", side_effect=factory), \
             patch.object(express_sdk, "_log_resolved_endpoint"), \
             patch.object(express_sdk, "execute_gemini_call", side_effect=execute):
            response = await self.pool.call(lambda: express_sdk.ExpressSDKUpstream().chat_completions(request, fast_request))
            clients[0].aio.aclose.assert_not_awaited()
            async def consume():
                return [chunk async for chunk in response.body_iterator]
            await asyncio.create_task(consume())
        self.assertEqual(len(clients), 2)
        self.assertEqual(proxies[0], proxies[1])
        for client in clients:
            client.aio.aclose.assert_awaited_once()
            client.close.assert_called_once()

    async def test_cancelled_consumer_cannot_cancel_pending_cleanup(self):
        entered, proceed = asyncio.Event(), asyncio.Event()
        async def cleanup():
            entered.set()
            await proceed.wait()
        async def upstream():
            register_request_cleanup(cleanup)
            return JSONResponse({"ok": True})
        task = asyncio.create_task(self.pool.call(upstream))
        await entered.wait()
        task.cancel()
        proceed.set()
        await asyncio.gather(task, return_exceptions=True)
        if self.pool.cleanup_tasks:
            await asyncio.gather(*list(self.pool.cleanup_tasks))
        self.assertEqual(self.pool.generation.references, 0)


class ConsoleTests(unittest.TestCase):
    def test_console_authentication_and_subscription_redaction(self):
        import main
        with patch("proxy_pool_api.proxy_pool") as manager:
            manager.status.return_value = {"enabled": False, "subscription_configured": True, "nodes": []}
            client = TestClient(main.app, base_url="https://testserver")
            self.assertEqual(client.get("/api/proxy-pool").status_code, 401)
            self.assertEqual(client.post("/api/proxy-pool", json={"enabled": False}).status_code, 401)
            self.assertEqual(client.post("/api/login", json={"password": main.config.API_KEY}).status_code, 200)
            response = client.get("/api/proxy-pool")
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(SECRET_URL, response.text)
            html = client.get("/").text
            self.assertIn('id="proxy-pool-url" type="password"', html)
            self.assertIn("saveProxyPool", html)
            self.assertNotIn("setInterval(loadProxyPool", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
