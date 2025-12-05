import docker
import logging
import asyncio
import docker.errors
from core.logger import SessionLocal, SandboxReport
from config.settings import settings

# This function contains blocking Docker API calls, so we run it in a separate thread.
def _blocking_sandbox_task(ip, payload):
    """Runs the suspicious payload in an isolated Docker container (Synchronous)."""
    client = docker.from_env()
    report_log = ""
    risk = "Low"
    
    try:
        # NOTE: If using ARM/MIPS malware, use a base image with qemu-user-static installed.
        # For simple command testing, alpine:latest is fine.
        container = client.containers.run(
            settings.DOCKER_IMAGE,
            command=f"/bin/sh -c '{payload}'",
            detach=True,
            mem_limit="64m",
            network_disabled=False,
            remove=True # Auto-clean container after analysis
        )
        
        # Wait for result or timeout
        try:
            result = container.wait(timeout=settings.SANDBOX_TIMEOUT)
            logs = container.logs().decode('utf-8', errors='ignore')
        except Exception:
            container.kill()
            logs = f"TIMEOUT ({settings.SANDBOX_TIMEOUT}s) - Suspicious long-running process."
            risk = "High"
            
        if "wget" in logs or "curl" in logs or "Error" not in logs:
             risk = "Medium"
        
        report_log = logs
        
        # Save Report
        session = SessionLocal()
        report = SandboxReport(source_ip=ip, command_executed=payload, output_log=report_log, risk_level=risk)
        session.add(report)
        session.commit()
        session.close()
        
        return logs

    except Exception as e:
        logging.error(f"Sandbox failure for {ip}: {e}")
        return str(e)


async def run_sandbox_analysis(ip, payload):
    """Public Async wrapper to run the blocking sandbox task in a thread."""
    logging.info(f"Sandboxing payload from {ip}: {payload}")
    # Use asyncio.to_thread to run the synchronous (blocking) docker client code
    await asyncio.to_thread(_blocking_sandbox_task, ip, payload)