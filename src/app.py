from fastapi import FastAPI, HTTPException, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
import structlog
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, Field, constr
from typing import Optional, Annotated, Dict
import uvicorn
from .services.contract_analyzer import ContractAnalyzer
from dotenv import load_dotenv
import os
import re
from web3 import Web3
import time
from .services.background_analyzer import BackgroundAnalyzer
import asyncio

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


async def init_contract_analyzer():
    try:
        analyzer = ContractAnalyzer(eth_url)
        await analyzer.initialize()  # Call async initialization
        return analyzer
    except Exception as e:
        logger.error("failed_to_initialize_analyzer", error=str(e))
        raise

contract_analyzer = None

# Initialize background analyzer
background_analyzer = None


@app.on_event("startup")
async def startup_event():
    global contract_analyzer, background_analyzer
    contract_analyzer = await init_contract_analyzer()
    background_analyzer = BackgroundAnalyzer(contract_analyzer.w3)
    await background_analyzer.start()


@app.on_event("shutdown")
async def shutdown_event():
    if background_analyzer:
        await background_analyzer.stop()

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


@app.get("/api/gas-analysis/{contract_address}")
@limiter.limit("5/minute")
async def analyze_gas_usage(
    request: Request,
    contract_address: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]{40}$")]
) -> Dict:
    """
    Analyze gas usage patterns and detect potential gas-related fraud for a contract
    """
    logger.info("gas_analysis_started", contract=contract_address)

    try:
        # Validate contract address
        if not Web3.is_address(contract_address):
            raise ValueError("Invalid contract address")

        # Perform gas analysis
        analysis = await contract_analyzer._analyze_gas_usage(contract_address)

        if "error" in analysis:
            logger.error("gas_analysis_error",
                         contract=contract_address,
                         error=analysis["error"])
            raise HTTPException(
                status_code=500,
                detail=f"Gas analysis failed: {analysis['error']}"
            )

        return analysis

    except ValueError as e:
        logger.error("validation_error", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        logger.error("gas_analysis_error", error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Internal server error during gas analysis"
        )


@app.get("/api/contract-history/{contract_address}")
@limiter.limit("5/minute")
async def get_contract_history(
    request: Request,
    contract_address: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]{40}$")],
    full_analysis: bool = Query(
        default=False, description="Wait for full analysis"),
    analysis_depth: str = Query(
        default="standard",
        enum=["quick", "standard", "deep"],
        description="Analysis depth level"
    ),
    include_holders: bool = Query(
        default=True, description="Include holder analysis"),
    include_governance: bool = Query(
        default=True, description="Include governance analysis"),
    time_range: str = Query(
        default="24h",
        enum=["1h", "24h", "7d", "30d"],
        description="Time range for analysis"
    )
):
    """
    Enhanced contract history analysis with configurable parameters
    """
    try:
        # Validate contract address
        if not Web3.is_address(contract_address):
            raise ValueError("Invalid contract address")

        # Configure analysis parameters based on inputs
        analysis_config = {
            "depth": analysis_depth,
            "include_holders": include_holders,
            "include_governance": include_governance,
            "time_range": time_range
        }

        # Queue detailed analysis with configuration
        task_id = await background_analyzer.queue_analysis(
            contract_address,
            analysis_config
        )

        if full_analysis:
            # Wait for analysis with dynamic timeout based on depth
            timeout = {
                "quick": 10,
                "standard": 30,
                "deep": 60
            }.get(analysis_depth, 30)

            for _ in range(timeout):
                task = background_analyzer.get_analysis_status(task_id)
                if task and task.status == "completed":
                    return task.result
                elif task and task.status == "failed":
                    raise HTTPException(
                        status_code=500,
                        detail=f"Analysis failed: {task.error}"
                    )
                await asyncio.sleep(1)

            raise HTTPException(
                status_code=408,
                detail="Analysis timeout - try getting status later"
            )
        else:
            # Return quick overview with enhanced metadata
            quick_overview = await contract_analyzer.get_quick_overview(contract_address)

            # Calculate estimated completion time based on analysis config
            estimated_seconds = {
                "quick": 10,
                "standard": 30,
                "deep": 60
            }.get(analysis_depth, 30)

            if time_range == "7d":
                estimated_seconds *= 2
            elif time_range == "30d":
                estimated_seconds *= 4

            return {
                **quick_overview,
                "task_id": task_id,
                "status": "analysis_pending",
                "analysis_config": analysis_config,
                "estimated_completion_time": estimated_seconds,
                "status_endpoint": f"/api/contract-history/{contract_address}/status/{task_id}"
            }

    except ValueError as e:
        logger.error("validation_error", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("history_retrieval_error", error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve contract history"
        )


@app.get("/api/contract-history/{contract_address}/status/{task_id}")
async def get_analysis_status(
    contract_address: str,
    task_id: str
):
    """Get the status of a detailed analysis task"""
    task = background_analyzer.get_analysis_status(task_id)
    if not task:
        raise HTTPException(
            status_code=404,
            detail="Analysis task not found"
        )

    if task.status == "completed":
        return task.result
    elif task.status == "failed":
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {task.error}"
        )
    else:
        return {
            "status": task.status,
            "contract_address": contract_address,
            "task_id": task_id,
            "started_at": task.start_time,
            "elapsed_time": time.time() - task.start_time
        }


def start():
    """Launched with `python -m src.app` at root level"""
    port = int(os.getenv("PORT", "8000"))
    print(f"Starting server on port {port}")
    uvicorn.run("src.app:app",
                host="0.0.0.0",
                port=port,
                reload=True)  # Enable auto-reload for development


if __name__ == "__main__":
    start()
