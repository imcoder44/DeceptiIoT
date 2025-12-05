import subprocess
import logging
import asyncio
from telegram import Bot
from config.settings import settings
from core.logger import SessionLocal, Attack

def block_ip(ip_address):
    if not settings.ENABLE_BLOCKING:
        return False
    
    try:
        # Check if already blocked
        check = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"], capture_output=True)
        if check.returncode == 0:
            return True 

        logging.warning(f"ACTION: Blocking malicious IP: {ip_address}")
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        
        session = SessionLocal()
        attacker = session.query(Attack).filter_by(ip=ip_address).first()
        if attacker:
            attacker.blocked = True
            session.commit()
        session.close()
        return True
    except Exception as e:
        logging.error(f"Iptables Block Error: {e}")
        return False

def unblock_ip(ip_address):
    # We assume success in DB even if iptables fails (e.g. rule didn't exist)
    try:
        logging.info(f"Unblocking IP: {ip_address}")
        # Use check=False so python doesn't crash if the rule is already gone
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=False)
        
        session = SessionLocal()
        attacker = session.query(Attack).filter_by(ip=ip_address).first()
        if attacker:
            attacker.blocked = False
            # Reset score so they aren't immediately re-blocked
            attacker.score = 0 
            session.commit()
        session.close()
        return True
    except Exception as e:
        logging.error(f"Failed to unblock {ip_address}: {e}")
        return False

# async def send_telegram_alert(message):
#     if not settings.ENABLE_TELEGRAM:
#         return
#     try:
#         bot = Bot(token=settings.TELEGRAM_TOKEN)
#         await asyncio.to_thread(bot.send_message, chat_id=settings.TELEGRAM_CHAT_ID, text=message)
#     except Exception as e:
#         logging.error(f"Failed to send Telegram alert: {e}")

# --- TELEGRAM ALERT FUNCTION (THE MISSING ATTRIBUTE) ---
async def send_telegram_alert(message):
    if not settings.ENABLE_TELEGRAM:
        return
    try:
        # Note: We run the synchronous Bot.send_message in a thread 
        # using asyncio.to_thread because it's being called from an async context.
        bot = Bot(token=settings.TELEGRAM_TOKEN)
        await asyncio.to_thread(bot.send_message, chat_id=settings.TELEGRAM_CHAT_ID, text=message)
        logging.info("Telegram alert sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send Telegram alert: {e}. Check token/chat ID and internet connection.")