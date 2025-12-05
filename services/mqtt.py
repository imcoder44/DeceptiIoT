import asyncio
import logging
from core.logger import log_event
from core.detector import analyze_event

class MqttHoneypot:
    def __init__(self, host='0.0.0.0', port=1883):
        self.host = host
        self.port = port

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        ip = addr[0]
        
        try:
            # MQTT CONNECT packet reading (simplified)
            data = await reader.read(1024)
            if data and data[0] == 0x10: # CONNECT packet
                # Extract length and protocol name roughly
                evt = log_event(ip, self.port, "MQTT", "CONNECT Packet Received")
                await analyze_event(evt)
                
                # Send CONNACK (Success)
                connack = b'\x20\x02\x00\x00' 
                writer.write(connack)
                await writer.drain()
                
                # Listen for PUBLISH or SUBSCRIBE
                while True:
                    msg = await reader.read(1024)
                    if not msg: break
                    # Log generic activity
                    log_event(ip, self.port, "MQTT", f"Data: {msg.hex()}")
                    
        except Exception as e:
            pass
        finally:
            writer.close()

    async def start(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logging.info(f"MQTT Honeypot active on port {self.port}")
        async with server:
            await server.serve_forever()