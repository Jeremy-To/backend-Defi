from pydantic import BaseModel, Field
from typing import Optional
from typing_extensions import Annotated

class ContractRequest(BaseModel):
    contract_address: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]{40}$")]

class HealthResponse(BaseModel):
    status: str
    version: str

class AnalysisConfig(BaseModel):
    depth: str
    include_holders: bool
    include_governance: bool
    time_range: str 