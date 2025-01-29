from web3 import Web3
from typing import List, Dict
import asyncio
from dataclasses import dataclass
from enum import Enum
import os
from cachetools import TTLCache
import structlog
from prometheus_client import Counter, Histogram


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


logger = structlog.get_logger()

# Add metrics
ANALYSIS_COUNTER = Counter(
    'contract_analysis_total',
    'Total number of contract analyses'
)
ANALYSIS_DURATION = Histogram(
    'contract_analysis_duration_seconds',
    'Time spent analyzing contracts'
)


class ContractAnalyzer:
    def __init__(self, provider_url: str):
        self._cache = TTLCache(maxsize=100, ttl=3600)  # 1 hour cache
        print(f"Initializing ContractAnalyzer with URL: {provider_url}")
        if not provider_url:
            raise ValueError("Provider URL is required")

        # Initialize Web3 with better configuration
        self.w3 = Web3(Web3.HTTPProvider(
            provider_url,
            request_kwargs={
                'timeout': 30,
                'headers': {
                    'Content-Type': 'application/json',
                }
            }
        ))

        # Test connection with retries
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if self.w3.is_connected():
                    # Test with a simple call
                    block_number = self.w3.eth.block_number
                    print(f"Connected successfully. Latest block: {
                          block_number}")
                    return
            except Exception as e:
                print(f"Attempt {attempt + 1}/{max_retries} failed: {str(e)}")
                if attempt == max_retries - 1:
                    raise ConnectionError(f"Failed to connect after {
                                          max_retries} attempts")

    async def analyze_contract(self, contract_address: str) -> Dict:
        # Add caching
        cache_key = f"analysis_{contract_address}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        with ANALYSIS_DURATION.time():
            ANALYSIS_COUNTER.inc()
            try:
                result = await self._perform_analysis(contract_address)
                self._cache[cache_key] = result
                return result
            except Exception as e:
                logger.error("analysis_failed",
                             contract=contract_address,
                             error=str(e))
                raise

    async def _check_backdoor_functions(self, bytecode: str) -> List[Vulnerability]:
        """Check for potential backdoor functions"""
        vulnerabilities = []

        # Known dangerous function signatures
        suspicious_signatures = {
            "0x8da5cb5b": "owner()",
            "0xf2fde38b": "transferOwnership(address)",
            "0x24d7806c": "setAdmin(address)",
            "0x70480275": "addAdmin(address)",
            "0x5f6985ac": "setController(address)",
            "0x3cf252a9": "setOperator(address)",
            "0x79ba5097": "acceptOwnership()",
            "0x715018a6": "renounceOwnership()"
        }

        for signature, function_name in suspicious_signatures.items():
            if signature in bytecode:
                vulnerabilities.append(
                    Vulnerability(
                        type=VulnerabilityType.BACKDOOR_FUNCTION,
                        severity=Severity.HIGH,
                        description=f"Potential backdoor function detected: {
                            function_name}",
                        evidence=f"Function signature: {signature}"
                    )
                )

        return vulnerabilities

    async def _check_withdrawal_restrictions(self, bytecode: str) -> List[Vulnerability]:
        """Check for code patterns that might restrict withdrawals"""
        vulnerabilities = []

        restriction_patterns = {
            "0x62d91478": "Possible withdrawal blocking mechanism",
            "0x7c025200": "Suspicious withdrawal condition"
        }

        for pattern, description in restriction_patterns.items():
            if pattern in bytecode:
                vulnerabilities.append(
                    Vulnerability(
                        type=VulnerabilityType.WITHDRAWAL_BLOCK,
                        severity=Severity.HIGH,
                        description=description,
                        evidence=f"Pattern found: {pattern}"
                    )
                )

        return vulnerabilities

    async def _check_permissions(self, contract_address: str) -> List[Vulnerability]:
        """Analyze contract permissions and ownership structure"""
        vulnerabilities = []

        # Check for common permission-related issues
        try:
            # This is a simplified check - you'd want to add more sophisticated
            # permission analysis here
            code_size = len(self.w3.eth.get_code(contract_address))
            if code_size > 0:
                # Check for multiple admin roles
                admin_signatures = ["0x9f3ca536", "0xb7009613"]
                for sig in admin_signatures:
                    if sig in self.w3.eth.get_code(contract_address).hex():
                        vulnerabilities.append(
                            Vulnerability(
                                type=VulnerabilityType.SUSPICIOUS_PERMISSIONS,
                                severity=Severity.MEDIUM,
                                description="Multiple admin roles detected",
                                evidence=f"Admin signature found: {sig}"
                            )
                        )
        except Exception as e:
            print(f"Error checking permissions: {str(e)}")

        return vulnerabilities

    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate overall risk score based on vulnerabilities"""
        score = 0

        severity_weights = {
            Severity.HIGH: 30,
            Severity.MEDIUM: 15,
            Severity.LOW: 5
        }

        for vuln in vulnerabilities:
            score += severity_weights[vuln.severity]

        return min(score, 100)  # Cap at 100

    async def _analyze_transaction_patterns(self, contract_address: str) -> List[Vulnerability]:
        """Analyze recent transactions for suspicious patterns"""
        vulnerabilities = []

        try:
            # Reduce the block range for faster analysis
            latest_block = self.w3.eth.block_number
            from_block = latest_block - 100  # Reduced from 1000 to 100 blocks
            print(f"Analyzing transactions from block {
                  from_block} to {latest_block}")

            # Get transaction history with progress updates
            transactions = []
            for block_num in range(from_block, latest_block):
                if (block_num - from_block) % 10 == 0:  # Progress update every 10 blocks
                    print(f"Processing block {block_num} ({
                          ((block_num - from_block)/(latest_block - from_block))*100:.1f}%)")

                try:
                    block = self.w3.eth.get_block(
                        block_num, full_transactions=True)

                    # Add timeout for each block request
                    for tx in block.transactions:
                        if tx.get('to') and tx['to'].lower() == contract_address.lower():
                            transactions.append(tx)
                except Exception as block_error:
                    print(f"Error processing block {
                          block_num}: {str(block_error)}")
                    continue

            print(f"Found {len(transactions)} transactions")

            # Analyze patterns
            if transactions:
                # Check for large sudden outflows
                total_value = sum(int(tx.get('value', 0))
                                  for tx in transactions)
                if total_value > 0:
                    avg_value = total_value / len(transactions)

                    for tx in transactions:
                        # Check for unusually large transactions
                        if int(tx.get('value', 0)) > avg_value * 5:  # 5x average
                            vulnerabilities.append(
                                Vulnerability(
                                    type=VulnerabilityType.SUSPICIOUS_TRANSACTIONS,
                                    severity=Severity.HIGH,
                                    description="Unusually large transaction detected",
                                    evidence=f"Transaction hash: {tx.hash.hex() if hasattr(
                                        tx, 'hash') else tx.get('hash', 'Unknown')}, Value: {tx.get('value', 0)}"
                                )
                            )

        except Exception as e:
            print(f"Error analyzing transaction patterns: {str(e)}")

        return vulnerabilities

    async def _analyze_liquidity_risk(self, contract_address: str) -> List[Vulnerability]:
        """Analyze liquidity risks for DeFi contracts"""
        vulnerabilities = []

        try:
            # Check if contract is a token (has balanceOf function)
            token_code = self.w3.eth.get_code(contract_address)
            if "0x70a08231" in token_code.hex():  # balanceOf signature
                # Get top holders
                # Check liquidity pools
                # Check holder concentration
                pass

        except Exception as e:
            print(f"Error analyzing liquidity: {str(e)}")

        return vulnerabilities

    async def _get_transaction_summary(self, contract_address: str) -> Dict:
        """Get summary of recent transaction patterns"""
        try:
            latest_block = self.w3.eth.block_number
            from_block = latest_block - 100  # Reduced from 1000 to 100 blocks
            print(f"Getting transaction summary from block {
                  from_block} to {latest_block}")

            # Basic summary for now
            return {
                "total_transactions": "Analyzing last 100 blocks",
                "unique_senders": "In progress",
                "volume_24h": "Calculating",
                "largest_transaction": "Analyzing",
                "transaction_frequency": "Analyzing"
            }
        except Exception as e:
            print(f"Error getting transaction summary: {str(e)}")
            return {
                "total_transactions": "Error",
                "unique_senders": "Error",
                "volume_24h": "Error",
                "largest_transaction": "Error",
                "transaction_frequency": "Error"
            }

    async def _get_holder_statistics(self, contract_address: str) -> Dict:
        """Get statistics about token holders if applicable"""
        try:
            return {
                "total_holders": 0,  # To be implemented
                "top_holder_concentration": 0,
                "holder_distribution": "Concentrated/Distributed",
                "average_holding_time": "N/A"
            }
        except Exception as e:
            print(f"Error getting holder statistics: {str(e)}")
            return {}

    async def _check_reentrancy(self, bytecode: str) -> List[Vulnerability]:
        """Check for reentrancy vulnerabilities"""
        vulnerabilities = []

        # Check for external calls before state changes
        reentrancy_patterns = {
            "0x": "External call followed by state change",
            # Add more patterns
        }

        for pattern, description in reentrancy_patterns.items():
            if pattern in bytecode:
                vulnerabilities.append(
                    Vulnerability(
                        type=VulnerabilityType.REENTRANCY,
                        severity=Severity.HIGH,
                        description=description,
                        evidence=f"Pattern found: {pattern}"
                    )
                )

        return vulnerabilities

    async def _analyze_historical_data(self, contract_address: str) -> Dict:
        """Analyze historical contract behavior"""
        try:
            latest_block = self.w3.eth.block_number
            # Analyze last 30 days of data
            blocks_per_day = 7200  # approximate
            from_block = latest_block - (30 * blocks_per_day)

            historical_data = {
                "daily_transaction_volume": [],
                "unique_users_trend": [],
                "price_history": [],
                "liquidity_changes": [],
                "major_events": []
            }

            # Implementation details...

            return historical_data
        except Exception as e:
            print(f"Error analyzing historical data: {str(e)}")
            return {}

    async def _analyze_gas_usage(self, contract_address: str) -> Dict:
        """Analyze gas usage patterns and suggest optimizations"""
        try:
            latest_block = self.w3.eth.block_number
            from_block = latest_block - 1000

            gas_analysis = {
                "average_gas_used": 0,
                "highest_gas_operation": "",
                "optimization_suggestions": [],
                "estimated_savings": 0
            }

            # Analyze recent transactions
            transactions = []
            for block_num in range(from_block, latest_block):
                block = self.w3.eth.get_block(
                    block_num, full_transactions=True)
                for tx in block.transactions:
                    if tx.get('to') == contract_address:
                        transactions.append(tx)

            # Calculate metrics and generate suggestions
            # Implementation details...

            return gas_analysis
        except Exception as e:
            print(f"Error analyzing gas usage: {str(e)}")
            return {}

    async def analyze_token_contract(self, contract_address: str) -> Dict:
        """Comprehensive token analysis including supply, transfers, and trading patterns"""
        try:
            checksum_address = Web3.to_checksum_address(contract_address)

            # Basic ERC20 function signatures
            ERC20_SIGNATURES = {
                "totalSupply()": "0x18160ddd",
                "transfer(address,uint256)": "0xa9059cbb",
                "balanceOf(address)": "0x70a08231",
                "approve(address,uint256)": "0x095ea7b3",
                "allowance(address,address)": "0xdd62ed3e"
            }

            token_analysis = {
                "token_type": "Unknown",
                "total_supply": 0,
                "circulating_supply": 0,
                "holder_metrics": {},
                "transfer_patterns": {},
                "trading_analysis": {},
                "potential_risks": []
            }

            # Check if contract is a token
            code = self.w3.eth.get_code(checksum_address).hex()
            if all(sig in code for sig in ERC20_SIGNATURES.values()):
                token_analysis["token_type"] = "ERC20"

                # Analyze supply mechanics
                await self._analyze_supply_mechanics(checksum_address, token_analysis)

                # Analyze transfer restrictions
                await self._analyze_transfer_restrictions(checksum_address, token_analysis)

                # Analyze trading patterns
                await self._analyze_trading_patterns(checksum_address, token_analysis)

                # Check for honeypot characteristics
                await self._check_honeypot_characteristics(checksum_address, token_analysis)

            return token_analysis

        except Exception as e:
            print(f"Error in token analysis: {str(e)}")
            raise

    async def _analyze_supply_mechanics(self, contract_address: str, analysis: Dict) -> None:
        """Analyze token supply mechanics including minting and burning"""
        try:
            # Check for mint functions
            mint_signatures = ["0x40c10f19", "0xa0712d68"]
            burn_signatures = ["0x42966c68", "0x79cc6790"]

            code = self.w3.eth.get_code(contract_address).hex()

            if any(sig in code for sig in mint_signatures):
                analysis["potential_risks"].append({
                    "type": VulnerabilityType.TOKEN_SUPPLY_MANIPULATION,
                    "severity": Severity.HIGH,
                    "description": "Contract contains functions that can modify token supply"
                })

            # Check for deflationary mechanics
            if any(sig in code for sig in burn_signatures):
                analysis["token_type"] = "Deflationary ERC20"

        except Exception as e:
            print(f"Error analyzing supply mechanics: {str(e)}")

    async def _analyze_transfer_restrictions(self, contract_address: str, analysis: Dict) -> None:
        """Analyze transfer restrictions and limitations"""
        try:
            # Common transfer restriction patterns
            restriction_patterns = {
                "0x7c025200": "Max transaction amount",
                "0x8f98ce8f": "Cooldown between transfers",
                "0x4a417a45": "Blacklist functionality"
            }

            code = self.w3.eth.get_code(contract_address).hex()

            for pattern, description in restriction_patterns.items():
                if pattern in code:
                    analysis["transfer_patterns"][description] = True

        except Exception as e:
            print(f"Error analyzing transfer restrictions: {str(e)}")

    async def _analyze_trading_patterns(self, contract_address: str, analysis: Dict) -> None:
        """Analyze trading patterns and liquidity"""
        try:
            latest_block = self.w3.eth.block_number
            from_block = latest_block - 1000

            # Get recent transfers
            transfer_filter = {
                'fromBlock': from_block,
                'toBlock': 'latest',
                'address': contract_address
            }

            # Analyze trading volume and frequency
            analysis["trading_analysis"] = {
                "24h_volume": 0,
                "unique_traders": 0,
                "average_trade_size": 0,
                "largest_trade": 0
            }

        except Exception as e:
            print(f"Error analyzing trading patterns: {str(e)}")

    async def _check_honeypot_characteristics(self, contract_address: str, analysis: Dict) -> None:
        """Check for characteristics commonly associated with honeypot tokens"""
        try:
            honeypot_indicators = {
                "high_sell_tax": False,
                "restricted_selling": False,
                "hidden_owner_functions": False,
                "suspicious_code_patterns": False
            }

            code = self.w3.eth.get_code(contract_address).hex()

            # Check for suspicious patterns
            suspicious_patterns = [
                "0x8f98ce8f",  # Hidden cooldown
                "0x4a417a45",  # Hidden blacklist
                "0x7c025200"   # Hidden limits
            ]

            if any(pattern in code for pattern in suspicious_patterns):
                honeypot_indicators["suspicious_code_patterns"] = True
                analysis["potential_risks"].append({
                    "type": VulnerabilityType.HONEYPOT_RISK,
                    "severity": Severity.HIGH,
                    "description": "Contract contains patterns commonly found in honeypot tokens"
                })

            analysis["honeypot_indicators"] = honeypot_indicators

        except Exception as e:
            print(f"Error checking honeypot characteristics: {str(e)}")
