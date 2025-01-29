from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import structlog
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel
from typing import List, Optional
import uvicorn
from src.services.contract_analyzer import ContractAnalyzer
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Get the URL and print it for debugging
eth_url = os.getenv("ETHEREUM_RPC_URL")
if not eth_url:
    raise EnvironmentError("ETHEREUM_RPC_URL environment variable is not set")

print(f"Loading with Ethereum URL: {eth_url}")

try:
    app = FastAPI(title="DeFi Security Monitor")
    contract_analyzer = ContractAnalyzer(eth_url)
except Exception as e:
    print(f"Failed to initialize ContractAnalyzer: {str(e)}")
    raise

# Configure structured logging
logger = structlog.get_logger()

# Configure rate limiting
limiter = Limiter(key_func=get_remote_address)

# Add security middlewares
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["your-domain.com"])

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add metrics
Instrumentator().instrument(app).expose(app)

# Add health check
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

class ContractRequest(BaseModel):
    contract_address: str


@app.post("/api/analyze-contract")
@limiter.limit("10/minute")  # Add rate limiting
async def analyze_contract(request: ContractRequest):
    logger.info("contract_analysis_started", contract=request.contract_address)
    try:
        print(f"Received request to analyze contract: {request.contract_address}")
        analysis = await contract_analyzer.analyze_contract(request.contract_address)
        return analysis
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("contract_analysis_failed", 
                    contract=request.contract_address,
                    error=str(e))
        raise HTTPException(status_code=500, 
                          detail="Internal server error")


@app.get("/api/contract-history/{contract_address}")
async def get_contract_history(
    contract_address: str,
    days: Optional[int] = Query(default=30, le=365)
):
    """Get historical analysis of contract behavior"""
    try:
        history = await contract_analyzer._analyze_historical_data(contract_address)
        return history
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/gas-analysis/{contract_address}")
async def get_gas_analysis(contract_address: str):
    """Get gas usage analysis and optimization suggestions"""
    try:
        analysis = await contract_analyzer._analyze_gas_usage(contract_address)
        return analysis
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/similar-contracts/{contract_address}")
async def find_similar_contracts(contract_address: str):
    """Find similar contracts for comparison"""
    try:
        similar = await contract_analyzer._find_similar_contracts(contract_address)
        return similar
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/token-analysis/{contract_address}")
async def analyze_token(
    contract_address: str,
    include_holders: Optional[bool] = Query(default=True),
    include_trading: Optional[bool] = Query(default=True)
):
    """Perform comprehensive token analysis"""
    try:
        analysis = await contract_analyzer.analyze_token_contract(contract_address)
        return analysis
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"Error during token analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
