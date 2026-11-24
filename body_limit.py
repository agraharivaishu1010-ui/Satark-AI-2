"""ASGI request-body size limit that also covers requests without Content-Length."""
from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_body_size: int) -> None:
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = next(
            (value.decode("latin-1") for key, value in scope["headers"] if key.lower() == b"content-length"),
            None,
        )
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                await JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)(scope, receive, send)
                return
            if declared_size < 0:
                await JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)(scope, receive, send)
                return
            if declared_size > self.max_body_size:
                await JSONResponse({"detail": "Request body exceeds the size limit."}, status_code=413)(
                    scope, receive, send
                )
                return

        total_size = 0
        exceeded_limit = False

        async def limited_receive() -> Message:
            nonlocal total_size, exceeded_limit
            if exceeded_limit:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                total_size += len(message.get("body", b""))
                if total_size > self.max_body_size:
                    exceeded_limit = True
                    return {"type": "http.disconnect"}
            return message

        async def limited_send(message: Message) -> None:
            if not exceeded_limit:
                await send(message)

        await self.app(scope, limited_receive, limited_send)
        if exceeded_limit:
            await JSONResponse({"detail": "Request body exceeds the size limit."}, status_code=413)(
                scope, receive, send
            )
