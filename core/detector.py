import json
import logging
from datetime import datetime, timedelta
from core.logger import SessionLocal, Attack, Event
from core.responder import block_ip, send_telegram_alert
from core.sandbox import run_sandbox_analysis

try:
    with open("config/rules.json", "r") as f:
        RULES = json.load(f)
except:
    logging.error("Could not load config/rules.json. Detection disabled.")
    RULES = []

async def analyze_event(event: Event):
    if not event:
        return

    session = SessionLocal()
    try:
        attacker = session.query(Attack).filter_by(ip=event.ip).first()
        if not attacker:
            attacker = Attack(ip=event.ip, score=0, attack_type="Unknown")
            session.add(attacker)
        
        attacker.last_seen = datetime.now()
        current_score = 0
        triggered_rules = []
        
        # 1. Keyword Analysis
        payload_str = f"{event.payload} {event.username} {event.password}"
        for rule in RULES:
            if rule.get("keywords"):
                for keyword in rule["keywords"]:
                    if keyword.lower() in payload_str.lower():
                        current_score += rule["score"]
                        triggered_rules.append(rule["name"])
                        break
        
        attacker.score += current_score
        
        # Update Description if new rules triggered
        if triggered_rules:
            current_desc = attacker.attack_type if attacker.attack_type != "Unknown" else ""
            new_desc = ", ".join(triggered_rules)
            if new_desc not in current_desc:
                attacker.attack_type = f"{current_desc}, {new_desc}".strip(", ")

        session.commit()

        # Threshold Check
        if attacker.score >= 70 and not attacker.blocked:
            logging.warning(f"CRITICAL THREAT DETECTED FROM {event.ip}. Score: {attacker.score}")
            
            if event.payload and len(event.payload) > 3 and current_score >= 85:
                 await run_sandbox_analysis(event.ip, event.payload)

            block_ip(event.ip)
            
            alert_msg = f"🚨 DeceptiIoT Alert 🚨\nIP: {event.ip}\nReason: {attacker.attack_type}\nScore: {attacker.score}\nAction: BLOCKED"
            await send_telegram_alert(alert_msg)

    except Exception as e:
        logging.error(f"Detection Error: {e}")
    finally:
        session.close()