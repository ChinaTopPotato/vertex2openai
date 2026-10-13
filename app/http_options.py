from typing import Optional
from google.genai import types
import config as app_config


def get_http_options(
    base_url: Optional[str] = None,
) -> Optional[types.HttpOptions]:
    """构造 google-genai HTTP 选项：代理、自定义证书、base_url 与请求头。"""
    client_args = {}
    if app_config.PROXY_URL:
        client_args["proxy"] = app_config.PROXY_URL
    if app_config.SSL_CERT_FILE:
        client_args["verify"] = app_config.SSL_CERT_FILE

    options = {}
    base_url = base_url or (app_config.VERTEX_BASE_URL or None)
    if base_url:
        options["base_url"] = base_url
    if client_args:
        options["client_args"] = client_args
        options["async_client_args"] = client_args

    return types.HttpOptions(**options) if options else None
