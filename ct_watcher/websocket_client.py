"""WebSocket client for connecting to certstream server."""

import asyncio
import traceback
import websockets
import websockets.exceptions

from .config import (
    CERTSTREAM_WS_URL,
    WS_PING_INTERVAL,
    WS_PING_TIMEOUT,
    INITIAL_RECONNECT_DELAY,
    MAX_RECONNECT_DELAY,
)
from .state import state
from .processor import process_message, report_stats
from .console import log
from .file_watcher import start_file_watcher


async def run_websocket_client() -> None:
    """Run the WebSocket client with auto-reconnect."""
    log("[*] Starting CertStream watcher...")
    file_watcher_task = asyncio.create_task(start_file_watcher())
    stats_task = asyncio.create_task(report_stats())
    try:
        while True:
            try:
                log(f"[*] Connecting to {CERTSTREAM_WS_URL} ...")
                async with websockets.connect(
                    CERTSTREAM_WS_URL,
                    ping_interval=WS_PING_INTERVAL,
                    ping_timeout=WS_PING_TIMEOUT,
                ) as ws:
                    state.reconnect_delay = INITIAL_RECONNECT_DELAY
                    log("[*] WebSocket connection established")
                    async for message in ws:
                        msg = (
                            message if isinstance(message, str) else bytes(message).decode("utf-8")
                        )
                        asyncio.create_task(asyncio.to_thread(process_message, msg))
            except websockets.exceptions.ConnectionClosed as e:
                log(f"[!] WebSocket closed: {e}")
            except Exception as e:
                log(f"[!] Unexpected error in main loop: {e}")
                log(traceback.format_exc())

            log(f"[*] Reconnecting in {state.reconnect_delay} seconds...")
            await asyncio.sleep(state.reconnect_delay)
            state.reconnect_delay = min(state.reconnect_delay * 2, MAX_RECONNECT_DELAY)
    except (KeyboardInterrupt, asyncio.CancelledError):
        log("\n[*] Shutting down gracefully...")
    finally:
        file_watcher_task.cancel()
        stats_task.cancel()
        try:
            await file_watcher_task
        except asyncio.CancelledError:
            pass
        try:
            await stats_task
        except asyncio.CancelledError:
            pass
