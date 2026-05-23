#!/usr/bin/env python
"""
Startup script for LoginShield with proper graceful shutdown.
Run: python run.py
"""
import sys
import signal
import asyncio
import uvicorn
from app.redis_client import close_redis

server = None


async def shutdown():
    """Graceful shutdown handler."""
    print("\n🛑 Shutdown signal received. Closing connections...")
    await close_redis()
    print("✅ All connections closed")
    sys.exit(0)


def signal_handler(sig, frame):
    """Handle system signals (CTRL+C)."""
    print("\n🛑 Received interrupt signal")
    asyncio.create_task(shutdown())


if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)   # CTRL+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination

    config = uvicorn.Config(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
    server = uvicorn.Server(config)

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     🔐 LoginShield v3.0 - Anomaly Detection System          ║
    ║                                                              ║
    ║  🌐 Web Interface: http://localhost:8000/static/index.html  ║
    ║  📡 API Docs: http://localhost:8000/docs                    ║
    ║  🏥 Health Check: http://localhost:8000/health              ║
    ║                                                              ║
    ║  Press CTRL+C to gracefully shutdown the server             ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    try:
        asyncio.run(server.serve())
    except KeyboardInterrupt:
        print("\n✅ Server shutdown complete")
        sys.exit(0)
