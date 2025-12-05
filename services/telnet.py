import asyncio
import logging
import re
from core.logger import log_event
from core.detector import analyze_event

class TelnetHoneypot:
    def __init__(self, host='0.0.0.0', port=2323):
        self.host = host
        self.port = port

    # Helper to clean garbage characters (IAC negotiation bytes)
    def clean_input(self, data_bytes):
        text = data_bytes.decode('utf-8', errors='ignore')
        # Remove non-printable chars except common ones
        return re.sub(r'[^\x20-\x7E]', '', text).strip()

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        ip = addr[0]
        logging.info(f"New Telnet connection from {ip}")

        try:
            writer.write(b"\xff\xfd\x01") # IAC DO ECHO
            # Banner
            writer.write(b"IoT Device (Linux 3.14.0) - Login Required\r\n")
            
            # Username
            writer.write(b"Login: ")
            await writer.drain()
            raw_user = await reader.read(1024)
            username = self.clean_input(raw_user)
            
            # Password
            writer.write(b"Password: ")
            await writer.drain()
            raw_pass = await reader.read(1024)
            password = self.clean_input(raw_pass)

            # Log Credentials
            event = log_event(ip, self.port, "TELNET", f"AUTH_ATTEMPT", username, password)
            if event:
                await analyze_event(event)

            # Fake Shell interaction
            writer.write(b"\r\nWelcome to BusyBox v1.24.1\r\n# ")
            await writer.drain()

            while True:
                data = await reader.read(1024)
                if not data: break
                command = self.clean_input(data)
                
                if command:
                    # Log Command
                    evt = log_event(ip, self.port, "TELNET", command, username, password)
                    if evt:
                        await analyze_event(evt)
                    
                    # Fake Responses
                    if command in ["exit", "quit"]:
                        break
                    elif command == "ls":
                        writer.write(b"bin dev etc home proc tmp var usr\r\n")
                    elif command == "uname -a":
                        writer.write(b"Linux IoT-Gateway 3.14.0 MIPS\r\n")
                    elif "wget" in command or "curl" in command:
                        # Fake successful download response (High Fidelity Deception)
                        writer.write(b"Connecting... 200 OK. Saving to 'malware.sh'\r\n")
                        writer.write(b"100%[======================================>] 540         --.-K/s   in 0s\r\n")
                    else:
                        writer.write(f"sh: {command}: not found\r\n".encode())
                    
                    writer.write(b"# ")
                    await writer.drain()

        except Exception as e:
            # Silence connection reset errors for cleaner logs
            if not isinstance(e, ConnectionResetError):
                 logging.error(f"Telnet error: {e}")
        finally:
            writer.close()

    async def start(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logging.info(f"Telnet Honeypot active on port {self.port}")
        async with server:
            await server.serve_forever()