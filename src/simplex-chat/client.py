import asyncio
import json
import logging  # TODO create logger

import websockets.asyncio.client as ws

class Client:
    def __init__(self, uri="ws://localhost:5225"):
        self.uri = uri
        self.connection: ws.ClientConnection
        self.connected = False
        self.corr_id = 0
        self.waiting: dict[str, asyncio.Future[dict]] = {}  # TODO type
        self.running_client: asyncio.Task

    async def connect(self):
        self.connection = await ws.connect(uri=self.uri)
        self.connected = True
        self.running_client = asyncio.Task(self._run_client())
    
    async def close(self):
        self.running_client.cancel()
        self.connected = False
        await self.connection.close()

    async def _run_client(self):
        assert self.connected
        try:
            async for message in self.connection:
                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    logging.error(f"Json decode error: {repr(message)}")
                    continue
                if "corrId" in data:
                    corr_id = data["corrId"]
                    if corr_id not in self.waiting:
                        logging.error(f"Server responded to corrId {corr_id} but nothing is waiting for it")
                    else:
                        self.waiting[corr_id].set_result(data)
                else:
                    # TODO enqueue instead
                    print(data)
                
        except asyncio.CancelledError:
            raise
    
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()

    async def cmd_raw(self, cmd: str):
        assert self.connected
        self.corr_id += 1

        future = asyncio.Future[dict]()
        self.waiting[str(self.corr_id)] = future
        
        data = json.dumps({"corrId": str(self.corr_id), "cmd": cmd})
        await self.connection.send(data, text=True)

        return await future
