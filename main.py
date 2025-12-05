import asyncio
import logging
import uvicorn
import sys # Import sys for final exit
from core.logger import init_db
from services.telnet import TelnetHoneypot
from services.http_service import start_http_honeypot
from services.mqtt import MqttHoneypot
from dashboard.app import app

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("deceptiot.log"),
        logging.StreamHandler()
    ]
)

async def start_dashboard():
    config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(config)
    
    # ⚠️ CRITICAL: The uvicorn server needs a way to stop itself. 
    # We will await its serve() method, and it will raise an exception 
    # when manually stopped, allowing main() to handle it.
    await server.serve()

async def main():
    print("""
    ==============================================
      DECEPTIIoT - Deception Based IoT Honeypot
      Starting Simulation Engines...
    ==============================================
    """)
    
    # 1. Initialize Database
    init_db()
    
    # 2. Initialize Services (Instantiate objects)
    telnet = TelnetHoneypot(port=2323) 
    mqtt = MqttHoneypot(port=1883)
    
    # 3. Create a list of all tasks to manage
    all_tasks = [
        asyncio.create_task(telnet.start(), name='TelnetHoneypot'),
        asyncio.create_task(mqtt.start(), name='MqttHoneypot'),
        asyncio.create_task(start_http_honeypot(), name='HTTPHoneypot'),
        asyncio.create_task(start_dashboard(), name='DashboardServer')
    ]
    
    try:
        # 4. Wait for all tasks to complete (This is where the program blocks)
        await asyncio.gather(*all_tasks)
        
    except KeyboardInterrupt:
        print("\nShutting down DeceptiIoT gracefully...")
        
        # 5. Cancel all running tasks
        for task in all_tasks:
            if not task.done():
                task.cancel()
        
        # 6. Wait for all tasks to complete cancellation
        # We use return_exceptions=True to suppress the CancelledError traceback
        await asyncio.gather(*all_tasks, return_exceptions=True)
        
        print("DeceptiIoT shutdown complete.")


if __name__ == "__main__":
    try:
        # We run the main function directly
        asyncio.run(main())
    except KeyboardInterrupt:
        # This final catch is to ensure a clean exit from the process
        print("Process exited cleanly.")
        sys.exit(0)