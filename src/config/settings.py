import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # Strip any whitespace or comments from environment variables
    ETHEREUM_RPC_URL = os.getenv("ETHEREUM_RPC_URL", "").strip()
    PORT = int(os.getenv("PORT", "8000").strip().split(
        "#")[0])  # Remove any comments
    VERSION = "1.0.0"

    # Rate limiting settings
    RATE_LIMIT_ANALYZE = "10/minute"
    RATE_LIMIT_GAS = "5/minute"
    RATE_LIMIT_HISTORY = "5/minute"

    # Analysis timeouts
    ANALYSIS_TIMEOUT_QUICK = 10
    ANALYSIS_TIMEOUT_STANDARD = 30
    ANALYSIS_TIMEOUT_DEEP = 60


settings = Settings()
