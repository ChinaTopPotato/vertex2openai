from fastapi import Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from proxy_pool import proxy_pool, PoolUnavailable
from proxy_subscription import SubscriptionError


class ProxyPoolSettings(BaseModel):
    enabled: bool = False
    subscription_url: str = Field(default="", max_length=8192)
    name_filter: str = Field(default="", max_length=500)
    refresh: bool = False


def install_proxy_pool_routes(app, require_auth):
    @app.get("/api/proxy-pool")
    async def get_proxy_pool(_auth=Depends(require_auth)):
        return JSONResponse(proxy_pool.status(), headers={"Cache-Control": "no-store"})

    @app.post("/api/proxy-pool")
    async def update_proxy_pool(body: ProxyPoolSettings, _auth=Depends(require_auth)):
        try:
            state = await proxy_pool.configure(body.enabled, body.subscription_url,
                                               body.name_filter, body.refresh)
            return JSONResponse(state, status_code=202 if state["job"]["state"] in ("downloading", "checking") else 200,
                                headers={"Cache-Control": "no-store"})
        except SubscriptionError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except PoolUnavailable as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)

    @app.post("/api/proxy-pool/check-next")
    async def check_next_proxy(_auth=Depends(require_auth)):
        return await proxy_pool.check_next()
