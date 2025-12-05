from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from core.logger import SessionLocal, Event, Attack, SandboxReport
from core.responder import unblock_ip
import json

app = FastAPI()

app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")
templates = Jinja2Templates(directory="dashboard/templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    db = SessionLocal()
    
    total_attacks = db.query(Attack).count()
    recent_events = db.query(Event).order_by(Event.timestamp.desc()).limit(20).all()
    top_attackers = db.query(Attack).order_by(Attack.score.desc()).limit(5).all()
    blocked_ips = db.query(Attack).filter(Attack.blocked == True).all()
    
    db.close()
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "total_attacks": total_attacks,
        "recent_events": recent_events,
        "top_attackers": top_attackers,
        "blocked_ips": blocked_ips
    })

@app.post("/unblock")
async def unblock_attacker(ip: str = Form(...)):
    # Perform the unblock logic
    unblock_ip(ip)
    # Redirect back to the dashboard homepage instead of returning JSON
    return RedirectResponse(url="/", status_code=303)

# NEW API: Get all events for a specific IP
@app.get("/api/attacker/{ip}")
async def get_attacker_details(ip: str):
    db = SessionLocal()
    events = db.query(Event).filter(Event.ip == ip).order_by(Event.timestamp.desc()).all()
    
    data = [{
        "time": e.timestamp.strftime("%H:%M:%S"),
        "protocol": e.protocol,
        "payload": e.payload,
        "auth": f"{e.username}:{e.password}" if e.username else "-"
    } for e in events]
    
    db.close()
    return data