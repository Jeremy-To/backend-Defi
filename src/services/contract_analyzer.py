from web3 import Web3, AsyncWeb3
from typing import List, Dict, Optional
import asyncio
from dataclasses import dataclass
from enum import Enum
import os
from cachetools import TTLCache, cached
from functools import lru_cache
import structlog
from prometheus_client import Counter, Histogram
import time
from web3.providers import AsyncHTTPProvider
import certifi
import ssl
import concurrent.futures


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
        self.patterns: List[Dict] = []  # New: Store identified patterns
        self.risk_metrics: Dict = {}    # New: Store risk metrics
        self.holder_metrics: Dict = {}   # New: Store holder information
        self.interaction_metrics: Dict = {}  # New: Store interaction patterns
        self.volume_metrics: Dict = {}   # New: Store volume analysis
        # New: Track governance changes
        self.governance_changes: List[Dict] = []
        # New: Track security-related events
        self.security_events: List[Dict] = []


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

        # Create SSL context with certifi
        ssl_context = ssl.create_default_context(cafile=certifi.where())

        # Configure Web3 with async HTTP provider
        self.w3 = AsyncWeb3(
            AsyncHTTPProvider(
                provider_url,
                request_kwargs={
                    'timeout': 30,
                    'headers': {
                        'Content-Type': 'application/json',
                    },
                    'ssl': ssl_context  # Use the SSL context
                }
            )
        )
        self._initialized = False

        # Add caches for different operations
        self._events_cache = TTLCache(maxsize=100, ttl=300)  # 5 minutes cache
        self._modifications_cache = TTLCache(maxsize=100, ttl=300)
        self._transactions_cache = TTLCache(maxsize=100, ttl=300)

    async def initialize(self):
        """Async initialization method"""
        if self._initialized:
            return

        # Test connection with retries
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if await self.w3.is_connected():
                    # Test with a simple call
                    block_number = await self.w3.eth.block_number
                    print(f"Connected successfully. Latest block: {
                          block_number}")
                    self._initialized = True
                    return
            except Exception as e:
                print(f"Attempt {attempt + 1}/{max_retries} failed: {str(e)}")
                if attempt == max_retries - 1:
                    raise ConnectionError(
                        f"Failed to connect after {max_retries} attempts")

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

    async def _check_backdoor_functions(self, bytecode: bytes) -> List[Vulnerability]:
        """Check for potential backdoor functions"""
        vulnerabilities = []

        # Convert bytecode to hex string for pattern matching
        bytecode_hex = bytecode.hex()

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
            if signature[2:] in bytecode_hex:  # Remove '0x' prefix for comparison
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

    async def _check_withdrawal_restrictions(self, bytecode: bytes) -> List[Vulnerability]:
        """Check for code patterns that might restrict withdrawals"""
        vulnerabilities = []

        # Convert bytecode to hex string for pattern matching
        bytecode_hex = bytecode.hex()

        restriction_patterns = {
            "62d91478": "Possible withdrawal blocking mechanism",
            "7c025200": "Suspicious withdrawal condition"
        }

        for pattern, description in restriction_patterns.items():
            if pattern in bytecode_hex:
                vulnerabilities.append(
                    Vulnerability(
                        type=VulnerabilityType.WITHDRAWAL_BLOCK,
                        severity=Severity.HIGH,
                        description=description,
                        evidence=f"Pattern found: 0x{pattern}"
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
            code_size = len(await self.w3.eth.get_code(contract_address))
            if code_size > 0:
                # Check for multiple admin roles
                admin_signatures = ["0x9f3ca536", "0xb7009613"]
                for sig in admin_signatures:
                    if sig in await self.w3.eth.get_code(contract_address):
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
            latest_block = await self.w3.eth.block_number
            from_block = latest_block - 100  # Reduced from 1000 to 100 blocks
            print(
                f"Analyzing transactions from block {from_block} to {latest_block}")

            # Get transaction history with progress updates
            transactions = []
            for block_num in range(from_block, latest_block):
                if (block_num - from_block) % 10 == 0:  # Progress update every 10 blocks
                    print(
                        f"Processing block {block_num} ({((block_num - from_block)/(latest_block - from_block))*100:.1f}%)")

                try:
                    block = await self.w3.eth.get_block(
                        block_num, full_transactions=True)

                    # Add timeout for each block request
                    for tx in block.transactions:
                        if tx.get('to') and tx['to'].lower() == contract_address.lower():
                            transactions.append(tx)
                except Exception as block_error:
                    print(
                        f"Error processing block {block_num}: {str(block_error)}")
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
            token_code = await self.w3.eth.get_code(contract_address)
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
            latest_block = await self.w3.eth.block_number
            from_block = latest_block - 100  # Reduced from 1000 to 100 blocks
            print(
                f"Getting transaction summary from block {from_block} to {latest_block}")

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

    async def _check_reentrancy(self, bytecode: bytes) -> List[Vulnerability]:
        """Check for reentrancy vulnerabilities"""
        vulnerabilities = []

        # Convert bytecode to hex string for pattern matching
        bytecode_hex = bytecode.hex()

        # Check for external calls before state changes
        reentrancy_patterns = {
            "": "External call followed by state change",  # Add actual patterns
        }

        for pattern, description in reentrancy_patterns.items():
            if pattern and pattern in bytecode_hex:
                vulnerabilities.append(
                    Vulnerability(
                        type=VulnerabilityType.REENTRANCY,
                        severity=Severity.HIGH,
                        description=description,
                        evidence=f"Pattern found: 0x{pattern}"
                    )
                )

        return vulnerabilities

    async def _analyze_historical_data(self, contract_address: str) -> Dict:
        """Analyze historical contract behavior"""
        try:
            latest_block = await self.w3.eth.block_number
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
        """Analyze gas usage patterns and detect potential gas-related fraud"""
        try:
            # Await the block number call
            latest_block = await self.w3.eth.block_number
            from_block = latest_block - 100

            gas_analysis = {
                "average_gas_used": 0,
                "suspicious_patterns": [],
                "high_gas_transactions": [],
                "gas_spikes": [],
                "potential_gas_manipulation": False,
                "risk_level": "LOW"
            }

            logger.info("starting_gas_analysis",
                        contract=contract_address,
                        from_block=from_block,
                        to_block=latest_block)

            # Get transactions in batches
            batch_size = 10
            transactions = []
            gas_usages = []

            # Process blocks in parallel batches
            for batch_start in range(from_block, latest_block, batch_size):
                batch_end = min(batch_start + batch_size, latest_block)

                tasks = []
                for block_num in range(batch_start, batch_end):
                    tasks.append(self._get_block_transactions(
                        block_num, contract_address))

                batch_results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in batch_results:
                    if isinstance(result, Exception):
                        logger.error("batch_processing_error",
                                     error=str(result))
                        continue
                    if result:
                        transactions.extend(result)
                        gas_usages.extend(tx['gas_used'] for tx in result)

            if not transactions:
                return gas_analysis

            # Calculate basic statistics
            avg_gas = sum(gas_usages) / len(gas_usages)
            std_dev = (sum((x - avg_gas) ** 2 for x in gas_usages) /
                       len(gas_usages)) ** 0.5
            gas_analysis["average_gas_used"] = avg_gas

            # Detect suspicious patterns
            for tx in transactions:
                # 1. Check for abnormally high gas usage (> 2 standard deviations)
                if tx['gas_used'] > avg_gas + (2 * std_dev):
                    gas_analysis["high_gas_transactions"].append({
                        "tx_hash": tx['hash'],
                        "gas_used": tx['gas_used'],
                        "block_number": tx['block_number']
                    })

                # 2. Check for gas price manipulation
                if tx['gas_price'] > 0:
                    block_txs = [t for t in transactions
                                 if abs(t['block_number'] - tx['block_number']) <= 5]
                    if len(block_txs) >= 3:
                        avg_block_gas_price = sum(
                            t['gas_price'] for t in block_txs) / len(block_txs)
                        if tx['gas_price'] > avg_block_gas_price * 3:
                            gas_analysis["suspicious_patterns"].append({
                                "type": "gas_price_manipulation",
                                "tx_hash": tx['hash'],
                                "gas_price": tx['gas_price'],
                                "avg_gas_price": avg_block_gas_price
                            })

            # 3. Detect gas spikes (sudden increases in gas usage)
            for i in range(1, len(transactions)):
                curr_gas = transactions[i]['gas_used']
                prev_gas = transactions[i-1]['gas_used']

                if curr_gas > prev_gas * 3:  # Gas usage tripled
                    gas_analysis["gas_spikes"].append({
                        "tx_hash": transactions[i]['hash'],
                        "gas_increase": curr_gas - prev_gas,
                        "block_number": transactions[i]['block_number']
                    })

            # 4. Check for consistent high gas usage pattern
            high_gas_count = len(gas_analysis["high_gas_transactions"])
            # More than 20% high gas transactions
            if high_gas_count > len(transactions) * 0.2:
                gas_analysis["potential_gas_manipulation"] = True

            # Determine risk level
            if (len(gas_analysis["suspicious_patterns"]) > 3 or
                len(gas_analysis["gas_spikes"]) > 5 or
                    gas_analysis["potential_gas_manipulation"]):
                gas_analysis["risk_level"] = "HIGH"
            elif (len(gas_analysis["suspicious_patterns"]) > 1 or
                  len(gas_analysis["gas_spikes"]) > 2):
                gas_analysis["risk_level"] = "MEDIUM"

            # Add fraud detection summary
            gas_analysis["fraud_detection_summary"] = {
                "suspicious_pattern_count": len(gas_analysis["suspicious_patterns"]),
                "gas_spike_count": len(gas_analysis["gas_spikes"]),
                "high_gas_transaction_count": high_gas_count,
                "recommendation": self._get_gas_recommendation(gas_analysis)
            }

            logger.info("gas_analysis_completed",
                        contract=contract_address,
                        risk_level=gas_analysis["risk_level"])

            return gas_analysis

        except Exception as e:
            logger.error("gas_analysis_failed",
                         contract=contract_address,
                         error=str(e))
            return {
                "error": f"Gas analysis failed: {str(e)}",
                "risk_level": "UNKNOWN"
            }

    async def _get_block_transactions(self, block_num: int, contract_address: str) -> list:
        """Helper method to get transactions for a specific block"""
        try:
            # Await the block call
            block = await self.w3.eth.get_block(block_num, full_transactions=True)
            block_transactions = []

            for tx in block.transactions:
                if tx.get('to') and tx['to'].lower() == contract_address.lower():
                    # Await the receipt call
                    receipt = await self.w3.eth.get_transaction_receipt(tx.hash)

                    tx_data = {
                        'hash': tx.hash.hex(),
                        'gas_used': receipt['gasUsed'],
                        'gas_price': tx.get('gasPrice', 0),
                        'block_number': block_num,
                        'timestamp': block.timestamp
                    }
                    block_transactions.append(tx_data)

            return block_transactions

        except Exception as e:
            logger.error("block_processing_error",
                         block=block_num,
                         error=str(e))
            return []

    def _get_gas_recommendation(self, gas_analysis: Dict) -> str:
        """Generate recommendations based on gas analysis"""
        if gas_analysis["risk_level"] == "HIGH":
            return ("High risk of gas manipulation detected. Exercise extreme caution. "
                    "Consider monitoring transactions closely and implementing gas limits.")
        elif gas_analysis["risk_level"] == "MEDIUM":
            return ("Some suspicious gas patterns detected. Monitor transactions "
                    "and implement basic gas safety measures.")
        else:
            return "No significant gas-related risks detected. Continue normal monitoring."

    async def analyze_token_contract(self, contract_address: str) -> Dict:
        """Comprehensive token analysis including supply, transfers, and trading patterns"""
        try:
            checksum_address = Web3.to_checksum_address(contract_address)

            token_analysis = {
                "contract_address": checksum_address,
                "token_type": "Unknown",
                "total_supply": 0,
                "circulating_supply": 0,
                "holder_metrics": {},
                "transfer_patterns": {},
                "trading_analysis": {},
                "potential_risks": [],
                "gas_analysis": {}
            }

            # First check if contract has token-like bytecode
            bytecode = await self.w3.eth.get_code(checksum_address)
            bytecode_hex = bytecode.hex()

            # Check for common ERC20 function signatures in bytecode
            erc20_signatures = {
                "70a08231": "balanceOf(address)",  # balanceOf
                "18160ddd": "totalSupply()",       # totalSupply
                "a9059cbb": "transfer(address,uint256)",  # transfer
                "dd62ed3e": "allowance(address,address)"  # allowance
            }

            # Check if contract has basic ERC20 functions
            is_potential_token = any(
                sig in bytecode_hex for sig in erc20_signatures)

            if not is_potential_token:
                return {
                    **token_analysis,
                    "error": "Contract does not appear to be an ERC20 token",
                    "details": "Missing basic ERC20 functions"
                }

            # Create ABI for basic ERC20 functions
            ERC20_ABI = [
                {
                    "constant": True,
                    "inputs": [],
                    "name": "totalSupply",
                    "outputs": [{"name": "", "type": "uint256"}],
                    "type": "function"
                },
                {
                    "constant": True,
                    "inputs": [{"name": "_owner", "type": "address"}],
                    "name": "balanceOf",
                    "outputs": [{"name": "balance", "type": "uint256"}],
                    "type": "function"
                }
            ]

            # Create contract instance
            contract = self.w3.eth.contract(
                address=checksum_address, abi=ERC20_ABI)

            try:
                # Try to get total supply with timeout
                total_supply = await asyncio.wait_for(
                    contract.functions.totalSupply().call(),
                    timeout=5.0
                )
                token_analysis["token_type"] = "ERC20"
                token_analysis["total_supply"] = total_supply

                try:
                    # Get circulating supply with timeout
                    contract_balance = await asyncio.wait_for(
                        contract.functions.balanceOf(checksum_address).call(),
                        timeout=5.0
                    )
                    token_analysis["circulating_supply"] = total_supply - \
                        contract_balance
                except (asyncio.TimeoutError, Exception) as e:
                    logger.warning("balance_fetch_error",
                                   contract=contract_address,
                                   error=str(e))
                    token_analysis["circulating_supply"] = total_supply

                # Continue with other analysis...
                await self._analyze_supply_mechanics(checksum_address, token_analysis)
                await self._analyze_transfer_restrictions(checksum_address, token_analysis)
                await self._analyze_trading_patterns(checksum_address, token_analysis)
                await self._check_honeypot_characteristics(checksum_address, token_analysis)

                # Add gas analysis
                token_analysis["gas_analysis"] = await self._analyze_gas_usage(checksum_address)

            except (asyncio.TimeoutError, Exception) as e:
                logger.error("token_analysis_error",
                             contract=contract_address,
                             error=str(e))
                token_analysis.update({
                    "error": f"Error analyzing token: {str(e)}",
                    "token_type": "Non-Standard Token or Contract",
                    "details": "Contract may not implement standard ERC20 interface"
                })

            return token_analysis

        except Exception as e:
            logger.error("token_analysis_failed",
                         contract=contract_address,
                         error=str(e))
            raise

    async def _analyze_supply_mechanics(self, contract_address: str, analysis: Dict) -> None:
        """Analyze token supply mechanics including minting and burning"""
        try:
            # Check for mint functions
            mint_signatures = ["0x40c10f19", "0xa0712d68"]
            burn_signatures = ["0x42966c68", "0x79cc6790"]

            code = await self.w3.eth.get_code(contract_address)

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

            code = await self.w3.eth.get_code(contract_address)

            for pattern, description in restriction_patterns.items():
                if pattern in code:
                    analysis["transfer_patterns"][description] = True

        except Exception as e:
            print(f"Error analyzing transfer restrictions: {str(e)}")

    async def _analyze_trading_patterns(self, contract_address: str, analysis: Dict) -> None:
        """Analyze trading patterns and liquidity"""
        try:
            latest_block = await self.w3.eth.block_number
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

            code = await self.w3.eth.get_code(contract_address)

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

    async def _perform_analysis(self, contract_address: str) -> Dict:
        """Perform comprehensive contract analysis"""
        try:
            # Convert address to checksum format if not already
            checksum_address = Web3.to_checksum_address(contract_address)

            # Get contract code
            bytecode = await self.w3.eth.get_code(checksum_address)
            code_size = len(bytecode)

            # Initialize results
            vulnerabilities = []

            # Run all security checks
            vulnerabilities.extend(await self._check_backdoor_functions(bytecode))
            vulnerabilities.extend(await self._check_withdrawal_restrictions(bytecode))
            vulnerabilities.extend(await self._check_permissions(checksum_address))
            vulnerabilities.extend(await self._check_reentrancy(bytecode))

            # Get transaction patterns
            suspicious_transactions = await self._analyze_transaction_patterns(checksum_address)
            vulnerabilities.extend(suspicious_transactions)

            # Get liquidity risks if applicable
            liquidity_risks = await self._analyze_liquidity_risk(checksum_address)
            vulnerabilities.extend(liquidity_risks)

            # Calculate overall risk score
            risk_score = self._calculate_risk_score(vulnerabilities)

            # Get additional analysis
            tx_summary = await self._get_transaction_summary(checksum_address)
            holder_stats = await self._get_holder_statistics(checksum_address)

            # Compile results
            return {
                "contract_address": checksum_address,
                "code_size": code_size,
                "risk_score": risk_score,
                "vulnerabilities": [v.__dict__ for v in vulnerabilities],
                "transaction_summary": tx_summary,
                "holder_stats": holder_stats,
                "timestamp": int(time.time())
            }

        except Exception as e:
            logger.error("analysis_failed",
                         contract=contract_address,
                         error=str(e))
            raise

    async def get_contract_history(self, contract_address: str) -> Dict:
        """Get comprehensive contract history including transactions, events, and modifications"""
        try:
            # Get latest block for reference
            latest_block = await self.w3.eth.block_number
            # Reduce look-back period to only 10 blocks (~ 2-3 minutes) for very fast results
            # Changed from 100 to 10 blocks
            from_block = max(0, latest_block - 10)

            # Check cache first
            cache_key = f"history_{contract_address}_{
                from_block}_{latest_block}"
            if cache_key in self._cache:
                return self._cache[cache_key]

            logger.info("fetching_contract_history",
                        contract=contract_address,
                        from_block=from_block,
                        to_block=latest_block)

            # Use asyncio.gather with shorter timeout
            try:
                # Set a timeout of 5 seconds for all operations
                history = ContractHistory()

                # Get only essential data first
                transactions = await asyncio.wait_for(
                    self._get_historical_transactions(
                        contract_address, from_block, latest_block),
                    timeout=3
                )
                history.transactions = transactions

                # Only fetch events and modifications if we have time left
                try:
                    events, modifications = await asyncio.wait_for(
                        asyncio.gather(
                            self._get_contract_events(
                                contract_address, from_block, latest_block),
                            self._get_contract_modifications(
                                contract_address, from_block, latest_block)
                        ),
                        timeout=2
                    )
                    history.events = events
                    history.modifications = modifications
                except asyncio.TimeoutError:
                    # Continue with just transactions if events/modifications timeout
                    history.events = []
                    history.modifications = []
                    logger.warning("events_fetch_timeout",
                                   contract=contract_address)

                # Quick analysis of patterns (simplified)
                history.analysis = await self._quick_analysis(history)

                result = {
                    "contract_address": contract_address,
                    "analysis_period": {
                        "from_block": from_block,
                        "to_block": latest_block,
                        "block_range": latest_block - from_block
                    },
                    "transactions": {
                        "total_count": len(history.transactions),
                        "unique_senders": len(set(tx.from_address for tx in history.transactions)),
                        "unique_receivers": len(set(tx.to_address for tx in history.transactions)),
                        "total_volume": sum(tx.value for tx in history.transactions)
                    },
                    "events": {
                        "total_count": len(history.events),
                        # Limit to 3
                        "event_types": list(set(event.event_type for event in history.events))[:3]
                    },
                    "modifications": {
                        "total_count": len(history.modifications)
                    },
                    "timestamp": int(time.time())
                }

                # Cache the result
                self._cache[cache_key] = result
                return result

            except asyncio.TimeoutError:
                # Return partial data if available
                return {
                    "contract_address": contract_address,
                    "status": "partial_data",
                    "transactions": {
                        "total_count": len(history.transactions) if hasattr(history, 'transactions') else 0
                    },
                    "timestamp": int(time.time()),
                    "note": "Analysis completed partially due to timeout"
                }

        except Exception as e:
            logger.error("history_analysis_failed",
                         contract=contract_address,
                         error=str(e))
            raise

    async def _quick_analysis(self, history: ContractHistory) -> Dict:
        """Simplified analysis for speed"""
        return {
            "risk_indicators": {
                "high_volume_transfers": bool(history.transactions),
                "contract_modifications": bool(history.modifications)
            }
        }

    async def _get_historical_transactions(
        self, contract_address: str, from_block: int, to_block: int
    ) -> List[HistoricalTransaction]:
        """Optimized transaction fetching"""
        cache_key = f"tx_{contract_address}_{from_block}_{to_block}"
        if cache_key in self._transactions_cache:
            return self._transactions_cache[cache_key]

        transactions = []
        try:
            # Get only the most recent blocks
            if to_block - from_block > 5:  # Limit to 5 blocks
                from_block = to_block - 5

            # Get all blocks at once
            blocks = await self.w3.eth.get_block(to_block, full_transactions=True)

            # Filter relevant transactions
            relevant_txs = [
                tx for tx in blocks.transactions
                if (tx.get('to') and tx['to'].lower() == contract_address.lower()) or
                   (tx.get('from') and tx['from'].lower()
                    == contract_address.lower())
            ][:5]  # Limit to 5 transactions

            if relevant_txs:
                # Get receipts in parallel
                receipts = await asyncio.gather(
                    *[self.w3.eth.get_transaction_receipt(tx.hash) for tx in relevant_txs]
                )

                for tx, receipt in zip(relevant_txs, receipts):
                    transactions.append(HistoricalTransaction(
                        timestamp=blocks.timestamp,
                        transaction_hash=tx.hash.hex(),
                        from_address=tx['from'],
                        to_address=tx.get('to', ''),
                        value=tx.get('value', 0),
                        block_number=tx['blockNumber'],
                        gas_used=receipt['gasUsed'],
                        success=(receipt['status'] == 1)
                    ))

            if transactions:
                self._transactions_cache[cache_key] = transactions

        except Exception as e:
            logger.error("failed_to_fetch_transactions", error=str(e))
            return []

        return transactions

    async def _get_contract_events(
        self, contract_address: str, from_block: int, to_block: int
    ) -> List[ContractEvent]:
        """Fetch and analyze contract events"""
        cache_key = f"events_{contract_address}_{from_block}_{to_block}"
        if cache_key in self._events_cache:
            return self._events_cache[cache_key]

        events = []
        try:
            # Common ERC20 event signatures
            event_signatures = {
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer",
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": "Approval",
                "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31": "OwnershipTransferred",
            }

            # Get logs for the contract
            logs = await self.w3.eth.get_logs({
                'address': contract_address,
                'fromBlock': from_block,
                'toBlock': to_block
            })

            for log in logs:
                # Get the block timestamp
                block = await self.w3.eth.get_block(log['blockNumber'])

                # Convert topic0 (event signature) to hex string
                event_signature = log['topics'][0].hex(
                ) if log['topics'] else None
                event_type = event_signatures.get(event_signature, "Unknown")

                events.append(ContractEvent(
                    event_type=event_type,
                    timestamp=block['timestamp'],
                    transaction_hash=log['transactionHash'].hex(),
                    block_number=log['blockNumber'],
                    details={
                        'topics': [t.hex() for t in log['topics']],
                        'data': log['data']
                    }
                ))

            # Cache the results
            self._events_cache[cache_key] = events

        except Exception as e:
            logger.error("failed_to_fetch_events", error=str(e))
            # Continue with empty events list rather than failing completely
            pass

        return events

    async def _get_contract_modifications(
        self, contract_address: str, from_block: int, to_block: int
    ) -> List[ContractModification]:
        """Track contract modifications and upgrades"""
        cache_key = f"modifications_{contract_address}_{from_block}_{to_block}"
        if cache_key in self._modifications_cache:
            return self._modifications_cache[cache_key]

        modifications = []
        try:
            # Common upgrade/modification related event signatures
            upgrade_signatures = {
                "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b": "Upgraded",
                "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0": "OwnershipTransferred",
            }

            # Get logs for potential modifications
            logs = await self.w3.eth.get_logs({
                'address': contract_address,
                'fromBlock': from_block,
                'toBlock': to_block,
                'topics': [[sig for sig in upgrade_signatures.keys()]]
            })

            for log in logs:
                block = await self.w3.eth.get_block(log['blockNumber'])
                event_signature = log['topics'][0].hex()

                modifications.append(ContractModification(
                    timestamp=block['timestamp'],
                    transaction_hash=log['transactionHash'].hex(),
                    block_number=log['blockNumber'],
                    modification_type=upgrade_signatures.get(
                        event_signature, "Unknown"),
                    old_value=log['topics'][1].hex() if len(
                        log['topics']) > 1 else None,
                    new_value=log['topics'][2].hex() if len(
                        log['topics']) > 2 else None
                ))

            # Cache the results
            self._modifications_cache[cache_key] = modifications

        except Exception as e:
            logger.error("failed_to_fetch_modifications", error=str(e))
            # Continue with empty modifications list rather than failing completely
            pass

        return modifications

    async def _analyze_historical_patterns(self, history: ContractHistory) -> Dict:
        """Analyze historical data for suspicious patterns"""
        analysis = {
            "suspicious_patterns": [],
            "risk_indicators": {
                "high_volume_transfers": False,
                "frequent_ownership_changes": False,
                "unusual_gas_patterns": False,
                "contract_modifications": False
            }
        }

        try:
            # Analyze transaction patterns
            if history.transactions:
                # Check for high volume transfers
                total_value = sum(tx.value for tx in history.transactions)
                avg_value = total_value / len(history.transactions)

                for tx in history.transactions:
                    if tx.value > avg_value * 5:  # Arbitrary threshold
                        analysis["suspicious_patterns"].append({
                            "type": "high_value_transfer",
                            "transaction_hash": tx.transaction_hash,
                            "value": tx.value,
                            "timestamp": tx.timestamp
                        })
                        analysis["risk_indicators"]["high_volume_transfers"] = True

            # Analyze ownership changes
            ownership_changes = [
                event for event in history.events
                if event.event_type == "OwnershipTransferred"
            ]
            if len(ownership_changes) > 2:  # Arbitrary threshold
                analysis["risk_indicators"]["frequent_ownership_changes"] = True
                analysis["suspicious_patterns"].append({
                    "type": "frequent_ownership_changes",
                    "count": len(ownership_changes),
                    "changes": [
                        {
                            "transaction_hash": event.transaction_hash,
                            "timestamp": event.timestamp
                        } for event in ownership_changes
                    ]
                })

            # Analyze contract modifications
            if history.modifications:
                analysis["risk_indicators"]["contract_modifications"] = True
                analysis["suspicious_patterns"].append({
                    "type": "contract_modifications",
                    "count": len(history.modifications),
                    "modifications": [
                        {
                            "type": mod.modification_type,
                            "transaction_hash": mod.transaction_hash,
                            "timestamp": mod.timestamp
                        } for mod in history.modifications
                    ]
                })

        except Exception as e:
            logger.error("pattern_analysis_failed", error=str(e))
            # Return partial analysis rather than failing completely
            analysis["error"] = str(e)

        return analysis

    async def get_quick_overview(self, contract_address: str) -> Dict:
        """Get quick overview of contract without detailed analysis"""
        try:
            # Get basic contract info
            code = await self.w3.eth.get_code(contract_address)
            balance = await self.w3.eth.get_balance(contract_address)
            latest_block = await self.w3.eth.block_number

            # Get last block with transaction
            block = await self.w3.eth.get_block(latest_block, full_transactions=True)

            # Quick check for recent transactions
            recent_txs = [
                tx for tx in block.transactions
                if (tx.get('to') and tx['to'].lower() == contract_address.lower()) or
                   (tx.get('from') and tx['from'].lower()
                    == contract_address.lower())
            ][:5]  # Limit to 5 most recent

            return {
                "contract_address": contract_address,
                "basic_info": {
                    "code_size": len(code),
                    "balance": balance,
                    "has_code": len(code) > 0,
                },
                "recent_activity": {
                    "latest_block": latest_block,
                    "recent_transactions": len(recent_txs),
                    "is_active": len(recent_txs) > 0
                },
                "quick_status": {
                    "is_contract": len(code) > 0,
                    "has_recent_activity": len(recent_txs) > 0,
                    "current_balance": balance
                },
                "timestamp": int(time.time())
            }

        except Exception as e:
            logger.error("quick_overview_failed",
                         contract=contract_address,
                         error=str(e))
            return {
                "contract_address": contract_address,
                "error": "Failed to get quick overview",
                "timestamp": int(time.time())
            }
