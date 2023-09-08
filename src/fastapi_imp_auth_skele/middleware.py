from __future__ import annotations
from typing import TYPE_CHECKING
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from .service import validate_jwt

if TYPE_CHECKING:
    from fastapi import Response
    from starlette.middleware.base import RequestResponseEndpoint


class JWTAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:
        super(JWTAuthMiddleware, self).__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not "X-Token" in request.headers:
            return JSONResponse(status_code=403, content={"detail": "missing x-token header"})
        if not validate_jwt(request.headers["X-Token"]):
            return JSONResponse(status_code=403, content={"detail": "invalid token"})
        return await call_next(request)
