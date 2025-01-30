# Make src a proper package
from .services import ContractAnalyzer, BackgroundAnalyzer
from .models.contract_models import (
    VulnerabilityType,
    Severity,
    Vulnerability,
    ContractEvent,
    ContractModification,
    HistoricalTransaction,
    ContractHistory
)
from .config.settings import settings

__all__ = [
    'ContractAnalyzer',
    'BackgroundAnalyzer',
    'VulnerabilityType',
    'Severity',
    'Vulnerability',
    'ContractEvent',
    'ContractModification',
    'HistoricalTransaction',
    'ContractHistory',
    'settings'
]
