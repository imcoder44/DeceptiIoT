import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float
from sqlalchemy.orm import sessionmaker, declarative_base
from config.settings import settings

Base = declarative_base()

class Event(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now)
    ip = Column(String)
    port = Column(Integer)
    protocol = Column(String)
    payload = Column(Text, nullable=True)
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)

class Attack(Base):
    __tablename__ = 'attacks'
    ip = Column(String, primary_key=True)
    first_seen = Column(DateTime, default=datetime.now)
    last_seen = Column(DateTime, default=datetime.now)
    score = Column(Integer, default=0)
    blocked = Column(Boolean, default=False)
    location = Column(String, default="Unknown")
    attack_type = Column(String, default="Suspicious Activity") # <--- NEW COLUMN

class SandboxReport(Base):
    __tablename__ = 'sandbox_reports'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now)
    source_ip = Column(String)
    command_executed = Column(Text)
    output_log = Column(Text)
    risk_level = Column(String)

# Database Setup
engine = create_engine(settings.DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def log_event(ip, port, protocol, payload=None, username=None, password=None):
    session = SessionLocal()
    try:
        event = Event(ip=ip, port=port, protocol=protocol, payload=payload, username=username, password=password)
        session.add(event)
        session.commit()
        session.refresh(event) 
        session.expunge(event) 
        return event
    except Exception as e:
        logging.error(f"Error logging event: {e}")
        session.rollback()
        return None
    finally:
        session.close()