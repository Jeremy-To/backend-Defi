from fastapi import FastAPI, HTTPException, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
import structlog
from prometheus_fastapi_instrumentator import Instrumentator
from typing import Optional, Dict, Annotated
from pydantic import Field
import uvicorn
from web3 import Web3
import time
import asyncio

from .config.settings import settings
from .models.api_models import ContractRequest, HealthResponse, AnalysisConfig
from .services import ContractAnalyzer, BackgroundAnalyzer

# Configure logging
logger = structlog.get_logger()

# Initialize FastAPI app
app = FastAPI(
    title="DeFi Security Monitor",
    description="API for analyzing Ethereum smart contracts",
    version=settings.VERSION
)

# Initialize services
contract_analyzer = None
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
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Add metrics
Instrumentator().instrument(app).expose(app)

# Routes


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(status="healthy", version=settings.VERSION)


async def init_contract_analyzer():
    """Initialize the contract analyzer with the configured RPC URL"""
    try:
        if not settings.ETHEREUM_RPC_URL:
            raise EnvironmentError(
                "ETHEREUM_RPC_URL environment variable is not set")

        analyzer = ContractAnalyzer(settings.ETHEREUM_RPC_URL)
        await analyzer.initialize()
        return analyzer
    except Exception as e:
        logger.error("failed_to_initialize_analyzer", error=str(e))
        raise


@app.get("/api/token-analysis/{contract_address}")
@limiter.limit(settings.RATE_LIMIT_ANALYZE)
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
        # Convert to checksum address
        checksum_address = Web3.to_checksum_address(contract_address)

        logger.info("token_analysis_started",
                    contract=checksum_address,
                    include_holders=include_holders,
                    include_trading=include_trading)

        analysis = await contract_analyzer.analyze_token_contract(checksum_address)
        return analysis

    except ValueError as e:
        logger.error("validation_error", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("token_analysis_error", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/gas-analysis/{contract_address}")
@limiter.limit(settings.RATE_LIMIT_GAS)
async def analyze_gas_usage(
    request: Request,
    contract_address: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]{40}$")]
) -> Dict:
    """
    Analyze gas usage patterns and detect potential gas-related fraud
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
@limiter.limit(settings.RATE_LIMIT_HISTORY)
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

        # Configure analysis parameters
        analysis_config = {
            "depth": analysis_depth,
            "include_holders": include_holders,
            "include_governance": include_governance,
            "time_range": time_range
        }

        # Queue detailed analysis
        task_id = await background_analyzer.queue_analysis(contract_address, analysis_config)

        if full_analysis:
            # Get timeout based on analysis depth
            timeout = getattr(settings, f"ANALYSIS_TIMEOUT_{
                              analysis_depth.upper()}")

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
            # Return quick overview
            quick_overview = await contract_analyzer.get_quick_overview(contract_address)
            return {
                **quick_overview,
                "task_id": task_id,
                "status": "analysis_pending",
                "analysis_config": analysis_config,
                "estimated_completion_time": getattr(settings, f"ANALYSIS_TIMEOUT_{analysis_depth.upper()}"),
                "status_endpoint": f"/api/contract-history/{contract_address}/status/{task_id}"
            }

    except ValueError as e:
        logger.error("validation_error", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("history_retrieval_error", error=str(e))
        raise HTTPException(
            status_code=500, detail="Failed to retrieve contract history")


@app.post("/api/analyze-contract")
@limiter.limit(settings.RATE_LIMIT_ANALYZE)
async def analyze_contract(request: Request, contract_request: ContractRequest):
    """
    Analyze a smart contract for potential vulnerabilities and risks
    """
    try:
        # Validate contract address
        contract_address = contract_request.contract_address
        if not Web3.is_address(contract_address):
            raise ValueError("Invalid contract address")

        logger.info("contract_analysis_started", contract=contract_address)

        # Perform contract analysis
        analysis = await contract_analyzer.analyze_contract(contract_address)

        if "error" in analysis:
            logger.error("analysis_error", 
                        contract=contract_address,
                        error=analysis["error"])
            raise HTTPException(
                status_code=500,
                detail=f"Analysis failed: {analysis['error']}"
            )

        return analysis

    except ValueError as e:
        logger.error("validation_error", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("analysis_error", error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Internal server error during contract analysis"
        )
