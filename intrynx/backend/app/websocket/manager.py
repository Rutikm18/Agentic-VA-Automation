"""
WebSocket manager for real-time graph updates and live collaboration.

Provides:
- Broadcasting graph updates to connected clients
- Real-time node position updates during force simulation
- Live collaboration features (multiple users viewing same graph)
- Heartbeat/ping-pong for connection health monitoring
"""
from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from typing import Dict, Optional, Set
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect
import structlog

logger = structlog.get_logger()


class ConnectionManager:
    """Manages WebSocket connections with room-based broadcasting."""

    def __init__(self):
        self._rooms: Dict[str, Set[WebSocket]] = defaultdict(set)
        self._connections: Dict[WebSocket, str] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, room_id: str):
        """Accept connection and add to room."""
        await websocket.accept()
        async with self._lock:
            self._rooms[room_id].add(websocket)
            self._connections[websocket] = room_id
        logger.info("websocket.client_connected", room=room_id)

    async def disconnect(self, websocket: WebSocket):
        """Remove connection from room."""
        async with self._lock:
            room_id = self._connections.pop(websocket, None)
            if room_id and websocket in self._rooms[room_id]:
                self._rooms[room_id].discard(websocket)
        logger.info("websocket.client_disconnected", room=room_id)

    async def broadcast(self, room_id: str, message: dict, exclude: Optional[WebSocket] = None):
        """Broadcast message to all connections in a room."""
        if room_id not in self._rooms:
            return

        dead_connections = []
        for websocket in self._rooms[room_id]:
            if websocket == exclude:
                continue
            try:
                await websocket.send_json(message)
            except Exception:
                dead_connections.append(websocket)

        for ws in dead_connections:
            await self.disconnect(ws)

    async def send_personal(self, websocket: WebSocket, message: dict):
        """Send message to a specific connection."""
        try:
            await websocket.send_json(message)
        except Exception:
            await self.disconnect(websocket)

    async def get_room_clients(self, room_id: str) -> int:
        """Get number of connected clients in a room."""
        return len(self._rooms.get(room_id, set()))


class GraphWebSocketManager:
    """High-level manager for graph-specific WebSocket operations."""

    def __init__(self):
        self.manager = ConnectionManager()
        self._graph_states: Dict[str, dict] = {}

    async def handle_client(self, websocket: WebSocket, engagement_id: str):
        """Handle a new WebSocket client connection."""
        room_id = f"graph:{engagement_id}"
        await self.manager.connect(websocket, room_id)

        try:
            while True:
                data = await websocket.receive_text()
                try:
                    message = json.loads(data)
                    await self._handle_message(websocket, room_id, message)
                except json.JSONDecodeError:
                    await self.manager.send_personal(websocket, {
                        "type": "error",
                        "message": "Invalid JSON",
                        "timestamp": datetime.utcnow().isoformat(),
                    })
        except WebSocketDisconnect:
            await self.manager.disconnect(websocket)

    async def _handle_message(self, websocket: WebSocket, room_id: str, message: dict):
        """Handle incoming WebSocket messages."""
        msg_type = message.get("type")

        if msg_type == "ping":
            await self.manager.send_personal(websocket, {
                "type": "pong",
                "timestamp": datetime.utcnow().isoformat(),
            })

        elif msg_type == "graph.update":
            await self.manager.broadcast(room_id, {
                "type": "graph.updated",
                "data": message.get("data"),
                "timestamp": datetime.utcnow().isoformat(),
            }, exclude=websocket)

        elif msg_type == "graph.subscribe":
            await self.manager.send_personal(websocket, {
                "type": "graph.subscribed",
                "timestamp": datetime.utcnow().isoformat(),
            })

    async def broadcast_graph_update(self, engagement_id: str, graph_data: dict):
        """Broadcast graph data update to all subscribers."""
        room_id = f"graph:{engagement_id}"
        await self.manager.broadcast(room_id, {
            "type": "graph.data",
            "data": graph_data,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def broadcast_node_update(self, engagement_id: str, node_id: str, node_data: dict):
        """Broadcast a single node update."""
        room_id = f"graph:{engagement_id}"
        await self.manager.broadcast(room_id, {
            "type": "graph.node.updated",
            "node_id": node_id,
            "data": node_data,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def broadcast_layout_update(self, engagement_id: str, layout_type: str):
        """Broadcast layout change to all subscribers."""
        room_id = f"graph:{engagement_id}"
        await self.manager.broadcast(room_id, {
            "type": "graph.layout.changed",
            "layout": layout_type,
            "timestamp": datetime.utcnow().isoformat(),
        })