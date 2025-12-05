import os

class Settings:
    # General
    HOST_IP = "0.0.0.0"  # Listen on all interfaces
    DB_URL = "sqlite:///database/deceptiot.db"
    
    # Automated Response
    ENABLE_BLOCKING = True
    ENABLE_TELEGRAM = False  # Set to True after adding token
    TELEGRAM_TOKEN = "8586958259:AAG8jJqMf2oMtvKtXe62POGNzjiyBHMIJn0"
    TELEGRAM_CHAT_ID = "7744656352"
    
    # Sandbox
    DOCKER_IMAGE = "alpine:latest" # Lightweight image for sandboxing
    SANDBOX_TIMEOUT = 20 # seconds

settings = Settings()