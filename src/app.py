from fastapi import FastAPI, HTTPException, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
import structlog
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, Field, constr
from typing import Optional, Annotated
import uvicorn
from .services.contract_analyzer import ContractAnalyzer
from dotenv import load_dotenv
import os
import re

# Load environment variables
load_dotenv()

# Configure logging
logger = structlog.get_logger()

# Initialize FastAPI app
app = FastAPI(
    title="DeFi Security Monitor",
    description="API for analyzing Ethereum smart contracts",
    version="1.0.0"
)

# Get configuration from environment
eth_url = os.getenv("ETHEREUM_RPC_URL")
if not eth_url:
    raise EnvironmentError("ETHEREUM_RPC_URL environment variable is not set")

# Initialize services
try:
    contract_analyzer = ContractAnalyzer(eth_url)
except Exception as e:
    logger.error("failed_to_initialize_analyzer", error=str(e))
    raise

# Configure rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Add metrics
Instrumentator().instrument(app).expose(app)

# Models


class ContractRequest(BaseModel):
    contract_address: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]{40}$")]


class HealthResponse(BaseModel):
    status: str
    version: str

# Routes


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(status="healthy", version="1.0.0")


@app.post("/api/analyze-contract")
@limiter.limit("10/minute")
async def analyze_contract(
    request: Request,
    contract_request: ContractRequest
):
    """
    Analyze a smart contract for security vulnerabilities
    """
    logger.info("contract_analysis_started",
                contract=contract_request.contract_address)
    try:
        analysis = await contract_analyzer.analyze_contract(contract_request.contract_address)
        return analysis
    except ValueError as e:
        logger.error("validation_error", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("analysis_error", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/token-analysis/{contract_address}")
@limiter.limit("10/minute")
async def analyze_token(
    request: Request,
    contract_address: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]{40}$")],
    include_holders: Optional[bool] = Query(default=True),
    include_trading: Optional[bool] = Query(default=True)
):
    """
    Perform comprehensive token analysis
    """
    try:
        analysis = await contract_analyzer.analyze_token_contract(contract_address)
        return analysis
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("token_analysis_error", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


def start():
    """Launched with `python -m src.app` at root level"""
    uvicorn.run("src.app:app", host="0.0.0.0",
                port=int(os.getenv("PORT", "8000")),
                reload=True)  # Enable auto-reload for development


if __name__ == "__main__":
    start()
