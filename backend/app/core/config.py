from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NETTRACE_", case_sensitive=False)

    APP_NAME: str = "NetTrace"
    APP_VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    UPLOADS_DIR: Path = DATA_DIR / "uploads"
    REPORTS_DIR: Path = DATA_DIR / "reports"
    
    DATABASE_URL: str = ""
    MAX_UPLOAD_SIZE_MB: int = 100
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]

    # Detector thresholds
    PORT_SCAN_THRESHOLD: int = 15
    HOST_SCAN_THRESHOLD: int = 10
    CONNECTION_BURST_THRESHOLD: int = 20
    BURST_WINDOW_SECONDS: float = 2.0
    REPEATED_DNS_QUERY_THRESHOLD: int = 5
    PERIODIC_CONNECTION_MIN_COUNT: int = 4
    PERIODIC_CV_THRESHOLD: float = 0.2
    TRAFFIC_RATE_SPIKE_PPS: float = 100.0

    def init_directories(self):
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
        self.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        if not self.DATABASE_URL:
            db_path = self.DATA_DIR / "nettrace.db"
            self.DATABASE_URL = f"sqlite:///{db_path.as_posix()}"

settings = Settings()
settings.init_directories()
