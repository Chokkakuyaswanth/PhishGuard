from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import computed_field
from typing import List
import json


class Settings(BaseSettings):
    database_url: str = "sqlite+aiosqlite:///./phishguard.db"
    secret_key: str = "change-me-in-production"

    virustotal_api_key: str = ""
    urlhaus_api_key: str = ""
    cti_mock: bool = True

    ml_model_path: str = "ml/models/artifacts/phishguard_model.joblib"

    # Total wall-clock budget for all CTI providers combined; whatever has not
    # answered by then is reported as TIMEOUT. The extension scans every
    # navigation and needs a sub-500ms verdict, so it gets a tighter budget
    # than the dashboard, which can afford to wait for full enrichment.
    cti_budget_ms: int = 2500
    cti_budget_extension_ms: int = 300

    # stored as str so pydantic-settings never tries json.loads on it
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    host: str = "0.0.0.0"
    port: int = 8000

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @computed_field
    @property
    def cors_origins_list(self) -> List[str]:
        v = self.cors_origins.strip()
        if v.startswith("["):
            return json.loads(v)
        return [o.strip() for o in v.split(",") if o.strip()]


settings = Settings()
