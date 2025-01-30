from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional

class VulnerabilityType(str, Enum):
    BACKDOOR_FUNCTION = "BACKDOOR_FUNCTION"
    WITHDRAWAL_BLOCK = "WITHDRAWAL_BLOCK"
    SUSPICIOUS_PERMISSIONS = "SUSPICIOUS_PERMISSIONS"
    MALICIOUS_PATTERN = "MALICIOUS_PATTERN"
    SUSPICIOUS_TRANSACTIONS = "SUSPICIOUS_TRANSACTIONS"
    LIQUIDITY_RISK = "LIQUIDITY_RISK"
    REENTRANCY = "REENTRANCY"
    FLASH_LOAN_VULNERABILITY = "FLASH_LOAN_VULNERABILITY"
    PRICE_MANIPULATION = "PRICE_MANIPULATION"
    FRONT_RUNNING = "FRONT_RUNNING"
    UNCHECKED_EXTERNAL_CALL = "UNCHECKED_EXTERNAL_CALL"
    TOKEN_SUPPLY_MANIPULATION = "TOKEN_SUPPLY_MANIPULATION"
    DEFLATIONARY_MECHANISM = "DEFLATIONARY_MECHANISM"
    HONEYPOT_RISK = "HONEYPOT_RISK"

class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Vulnerability:
    type: VulnerabilityType
    severity: Severity
    description: str
    location: str = None
    evidence: str = None

@dataclass
class ContractEvent:
    event_type: str
    timestamp: int
    transaction_hash: str
    block_number: int
    details: dict

@dataclass
class ContractModification:
    timestamp: int
    transaction_hash: str
    block_number: int
    modification_type: str
    old_value: Optional[str]
    new_value: Optional[str]

@dataclass
class HistoricalTransaction:
    timestamp: int
    transaction_hash: str
    from_address: str
    to_address: str
    value: int
    block_number: int
    gas_used: int
    success: bool

@dataclass
class ContractHistory:
    def __init__(self):
        self.transactions: List[HistoricalTransaction] = []
        self.events: List[ContractEvent] = []
        self.modifications: List[ContractModification] = []
        self.analysis: dict = {}
        self.patterns: List[Dict] = []
        self.risk_metrics: Dict = {}
        self.holder_metrics: Dict = {}
        self.interaction_metrics: Dict = {}
        self.volume_metrics: Dict = {}
        self.governance_changes: List[Dict] = []
        self.security_events: List[Dict] = [] 