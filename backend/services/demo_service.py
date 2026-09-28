import asyncio
import json
import logging
import os
from typing import Any, Callable, Coroutine, List
from models.schemas import FlowRecord

logger = logging.getLogger("zyntrix.demo")

class DemoService:
    def __init__(self):
        self.is_running = False
        self.flows: List[FlowRecord] = []
        self.current_index = 0
        self.on_new_flow: Callable[[FlowRecord], Coroutine[Any, Any, None]] = None
        self._task: asyncio.Task = None
        self.load_data()

    def load_data(self):
        """Loads pre-generated demo flows from disk"""
        data_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "test_stream.json")
        if not os.path.exists(data_path):
            data_path = os.path.join(os.path.dirname(__file__), "..", "data", "test_stream.json")
            
        try:
            with open(data_path, "r") as f:
                raw_data = json.load(f)
                self.flows = [FlowRecord(**item) for item in raw_data]
            logger.info("Loaded %d demo flows from test_stream.json", len(self.flows))
        except Exception as e:
            logger.error("Failed to load demo data: %s", e)
            self.flows = []

    async def start(self):
        if self.is_running:
            return
        
        self.is_running = True
        self.current_index = 0
        logger.info("Demo started with %d flows", len(self.flows))
        
        if self._task and not self._task.done():
            self._task.cancel()
            
        # Background task for streaming
        self._task = asyncio.create_task(self._stream_data())

    def stop(self):
        self.is_running = False
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("Demo stopped")

    async def inject_flow(self, flow: FlowRecord):
        if self.on_new_flow:
            await self.on_new_flow(flow)

    async def _stream_data(self):
        try:
            while self.is_running and self.current_index < len(self.flows):
                flow = self.flows[self.current_index]
                if self.on_new_flow:
                    await self.on_new_flow(flow)
                
                self.current_index += 1
                await asyncio.sleep(0.5)
                
            if self.current_index >= len(self.flows):
                self.is_running = False
                logger.info("Demo finished — all %d flows streamed", self.current_index)
        except asyncio.CancelledError:
            logger.info("Demo stream cancelled")

demo_service = DemoService()
