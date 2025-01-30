from dataclasses import dataclass
from typing import Dict, Optional, List
import asyncio
import time
import structlog
from web3 import AsyncWeb3, Web3
from cachetools import TTLCache

logger = structlog.get_logger()

# Update the ERC20_ABI constant at the top of the file
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
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "from", "type": "address"},
            {"indexed": True, "name": "to", "type": "address"},
            {"indexed": False, "name": "value", "type": "uint256"}
        ],
        "name": "Transfer",
        "type": "event"
    }
]


@dataclass
class AnalysisTask:
    contract_address: str
    status: str  # 'pending', 'in_progress', 'completed', 'failed'
    start_time: float
    config: Dict  # Add config field
    result: Optional[Dict] = None
    error: Optional[str] = None


class BackgroundAnalyzer:
    def __init__(self, w3: AsyncWeb3):
        self.w3 = w3
        self._tasks: Dict[str, AnalysisTask] = {}
        self._cache = TTLCache(maxsize=100, ttl=3600)  # 1 hour cache
        self._analysis_queue = asyncio.Queue()
        self._worker_task = None
        self.ERC20_ABI = ERC20_ABI  # Add ABI to class

    async def start(self):
        """Start the background analysis worker"""
        if self._worker_task is None:
            self._worker_task = asyncio.create_task(self._analysis_worker())
            logger.info("background_analyzer_started")

    async def stop(self):
        """Stop the background analysis worker"""
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
            logger.info("background_analyzer_stopped")

    async def queue_analysis(self, contract_address: str, analysis_config: Dict) -> str:
        """Queue a contract for detailed analysis with configuration"""
        task_id = f"analysis_{contract_address}_{int(time.time())}"
        self._tasks[task_id] = AnalysisTask(
            contract_address=contract_address,
            status="pending",
            start_time=time.time(),
            config=analysis_config
        )
        await self._analysis_queue.put(task_id)
        return task_id

    def get_analysis_status(self, task_id: str) -> Optional[AnalysisTask]:
        """Get the status of an analysis task"""
        return self._tasks.get(task_id)

    async def _analysis_worker(self):
        """Background worker for processing analysis tasks"""
        while True:
            try:
                task_id = await self._analysis_queue.get()
                task = self._tasks[task_id]

                logger.info("starting_detailed_analysis",
                            contract=task.contract_address,
                            task_id=task_id,
                            config=task.config)

                task.status = "in_progress"

                try:
                    # Perform detailed analysis with config
                    result = await self._perform_detailed_analysis(
                        task.contract_address,
                        task.config
                    )
                    task.result = result
                    task.status = "completed"

                    # Cache the result
                    self._cache[task.contract_address] = result

                except Exception as e:
                    logger.error("analysis_failed",
                                 contract=task.contract_address,
                                 error=str(e))
                    task.status = "failed"
                    task.error = str(e)
                    task.result = {
                        "contract_address": task.contract_address,
                        "status": "failed",
                        "error": str(e),
                        "timestamp": int(time.time())
                    }

                finally:
                    self._analysis_queue.task_done()

            except Exception as e:
                logger.error("worker_error", error=str(e))
                await asyncio.sleep(1)  # Prevent tight loop on errors

    async def _perform_detailed_analysis(self, contract_address: str, config: Dict) -> Dict:
        """Enhanced comprehensive contract analysis with configuration"""
        latest_block = await self.w3.eth.block_number

        # Determine block range based on time_range config
        blocks_per_day = 7200  # approximate
        time_range_blocks = {
            "1h": blocks_per_day // 24,
            "24h": blocks_per_day,
            "7d": blocks_per_day * 7,
            "30d": blocks_per_day * 30
        }
        block_range = time_range_blocks.get(
            config["time_range"], blocks_per_day)
        from_block = max(0, latest_block - block_range)

        # Parallel data collection based on config
        tasks = [
            self._get_detailed_transactions(
                contract_address, from_block, latest_block),
            self._get_detailed_events(
                contract_address, from_block, latest_block)
        ]

        if config.get("include_holders", True):
            tasks.append(self._get_holder_distribution(contract_address))

        if config.get("include_governance", True):
            tasks.append(self._get_governance_history(contract_address))
            tasks.append(self._get_security_events(contract_address))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results based on config
        analysis_depth = config.get("depth", "standard")
        return self._process_analysis_results(
            contract_address, results, analysis_depth, config)

    async def _get_logs_with_pagination(self, params: Dict, max_blocks_per_query: int = 2000) -> List:
        """Get logs with automatic pagination and adaptive block range"""
        all_logs = []
        from_block = params['fromBlock']
        to_block = params.get('toBlock', 'latest')

        if to_block == 'latest':
            to_block = await self.w3.eth.block_number

        while from_block <= to_block:
            end_block = min(from_block + max_blocks_per_query - 1, to_block)

            try:
                # Update block range for this query
                current_params = {
                    **params,
                    'fromBlock': from_block,
                    'toBlock': end_block
                }

                logs = await self.w3.eth.get_logs(current_params)
                all_logs.extend(logs)

                # Move to next block range
                from_block = end_block + 1

            except Exception as e:
                if "Log response size exceeded" in str(e):
                    # Reduce block range and retry
                    max_blocks_per_query = max_blocks_per_query // 2
                    if max_blocks_per_query < 100:
                        # If block range is too small, try to extract suggested range from error
                        try:
                            import re
                            match = re.search(
                                r'\[0x([a-f0-9]+), 0x([a-f0-9]+)\]', str(e))
                            if match:
                                suggested_start = int(match.group(1), 16)
                                suggested_end = int(match.group(2), 16)
                                max_blocks_per_query = suggested_end - suggested_start
                        except:
                            max_blocks_per_query = 100

                    logger.warning("reducing_block_range",
                                   new_range=max_blocks_per_query,
                                   from_block=from_block)
                    continue
                else:
                    raise e

        return all_logs

    async def _get_holder_distribution(self, contract_address: str) -> Dict:
        """Analyze token holder distribution with pagination"""
        try:
            token_contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(contract_address),
                abi=self.ERC20_ABI
            )

            # Get decimals first with fallback
            try:
                decimals = await token_contract.functions.decimals().call()
            except Exception as e:
                logger.warning("decimals_fetch_error", error=str(e))
                decimals = 18  # Default to 18 decimals if not found

            current_block = await self.w3.eth.block_number
            from_block = max(0, current_block - 5000)

            # Get Transfer events with pagination and smaller block ranges
            params = {
                'address': contract_address,
                'fromBlock': from_block,
                'toBlock': 'latest',
                'topics': [
                    '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
                ]
            }

            try:
                transfer_events = await self._get_logs_with_pagination(params, max_blocks_per_query=1000)
            except Exception as e:
                logger.error("transfer_events_fetch_error", error=str(e))
                transfer_events = []

            # Process transfers
            holder_balances = {}
            for event in transfer_events:
                try:
                    from_addr = '0x' + event['topics'][1].hex()[-40:]
                    to_addr = '0x' + event['topics'][2].hex()[-40:]

                    # Handle different data formats
                    if isinstance(event['data'], str):
                        if event['data'].startswith('0x'):
                            value = int(event['data'], 16)
                        else:
                            value = int(event['data'])
                    elif isinstance(event['data'], bytes):
                        value = int.from_bytes(event['data'], byteorder='big')
                    else:
                        continue

                    if value > 0:
                        holder_balances[from_addr] = holder_balances.get(
                            from_addr, 0) - value
                        holder_balances[to_addr] = holder_balances.get(
                            to_addr, 0) + value

                except Exception as e:
                    logger.error("event_processing_error",
                                 error=str(e),
                                 event_hash=event['transactionHash'].hex())
                    continue

            # Verify current balances in smaller batches
            holder_addresses = [
                addr for addr, balance in holder_balances.items()
                if balance > 0
            ]
            verified_balances = {}

            # Reduce batch size for better reliability
            batch_size = 50
            for i in range(0, len(holder_addresses), batch_size):
                batch = holder_addresses[i:i + batch_size]
                try:
                    balance_coros = [
                        token_contract.functions.balanceOf(addr).call()
                        for addr in batch
                    ]
                    balances = await asyncio.gather(*balance_coros, return_exceptions=True)

                    for addr, balance in zip(batch, balances):
                        if not isinstance(balance, Exception) and balance > 0:
                            verified_balances[addr] = balance / \
                                (10 ** decimals)

                except Exception as e:
                    logger.error("balance_check_error",
                                 error=str(e),
                                 batch_start=i,
                                 batch_size=batch_size)
                    continue

            try:
                total_supply = await token_contract.functions.totalSupply().call()
                total_supply = total_supply / (10 ** decimals)
            except Exception as e:
                logger.error("total_supply_fetch_error", error=str(e))
                total_supply = sum(verified_balances.values())

            # Get top holders with proper error handling
            try:
                top_holders = sorted(
                    [(addr, bal) for addr, bal in verified_balances.items()],
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            except Exception as e:
                logger.error("top_holders_sort_error", error=str(e))
                top_holders = []

            return {
                "total_holders": len(verified_balances),
                "total_supply": total_supply,
                "balance_distribution": verified_balances,
                "top_holders": top_holders,
                "concentration_metrics": {
                    "top_10_percentage": sum(bal for _, bal in top_holders) / total_supply * 100 if total_supply > 0 else 0,
                    "average_balance": total_supply / len(verified_balances) if verified_balances else 0
                }
            }

        except Exception as e:
            logger.error("holder_distribution_error", error=str(e))
            return {
                "error": str(e),
                "total_holders": 0,
                "balance_distribution": {},
                "top_holders": []
            }

    async def _get_security_events(self, contract_address: str) -> Dict:
        """Get security-related events with pagination"""
        try:
            security_signatures = {
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": "Approval",
                "0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258": "Paused",
                "0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa": "Unpaused"
            }

            latest_block = await self.w3.eth.block_number
            from_block = max(0, latest_block - 10000)

            params = {
                'address': contract_address,
                'fromBlock': from_block,
                'toBlock': 'latest',
                'topics': [[sig for sig in security_signatures.keys()]]
            }

            logs = await self._get_logs_with_pagination(params)

            security_events = []
            for log in logs:
                event_sig = log['topics'][0].hex()
                security_events.append({
                    'type': security_signatures.get(event_sig, "Unknown"),
                    'transaction_hash': log['transactionHash'].hex(),
                    'block_number': log['blockNumber']
                })

            return {
                "total_events": len(security_events),
                "events": security_events
            }

        except Exception as e:
            logger.error("security_events_error", error=str(e))
            return {"error": str(e)}

    async def _get_detailed_transactions(self, contract_address: str, from_block: int, to_block: int):
        """Get detailed transaction history with batching"""
        transactions = []
        batch_size = 50  # Process 50 blocks at a time

        try:
            for batch_start in range(from_block, to_block, batch_size):
                batch_end = min(batch_start + batch_size, to_block)

                # Get blocks in parallel
                blocks = await asyncio.gather(*[
                    self.w3.eth.get_block(block_num, full_transactions=True)
                    for block_num in range(batch_start, batch_end)
                ])

                for block in blocks:
                    # Filter transactions for this contract
                    contract_txs = [
                        tx for tx in block.transactions
                        if (tx.get('to') and tx['to'].lower() == contract_address.lower()) or
                           (tx.get('from') and tx['from'].lower(
                           ) == contract_address.lower())
                    ]

                    if contract_txs:
                        # Get receipts in parallel
                        receipts = await asyncio.gather(*[
                            self.w3.eth.get_transaction_receipt(tx.hash)
                            for tx in contract_txs
                        ])

                        for tx, receipt in zip(contract_txs, receipts):
                            transactions.append({
                                'hash': tx.hash.hex(),
                                'from': tx['from'],
                                'to': tx.get('to', ''),
                                'value': tx.get('value', 0),
                                'block_number': tx['blockNumber'],
                                'timestamp': block.timestamp,
                                'gas_used': receipt['gasUsed'],
                                'success': receipt['status'] == 1,
                                'method_id': tx.input[:10] if len(tx.input) >= 10 else None
                            })

        except Exception as e:
            logger.error("transaction_fetch_error", error=str(e))

        return transactions

    async def _get_detailed_events(self, contract_address: str, from_block: int, to_block: int):
        """Get and decode contract events with pagination"""
        events = []
        try:
            # Common event signatures
            event_signatures = {
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer",
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": "Approval",
                "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31": "OwnershipTransferred",
            }

            # Get logs with pagination
            params = {
                'address': contract_address,
                'fromBlock': from_block,
                'toBlock': to_block
            }

            logs = await self._get_logs_with_pagination(params, max_blocks_per_query=500)

            # Process logs in batches to avoid timeouts
            batch_size = 50
            for i in range(0, len(logs), batch_size):
                batch = logs[i:i + batch_size]

                # Get blocks for this batch
                block_numbers = list(set(log['blockNumber'] for log in batch))
                blocks = {
                    num: await self.w3.eth.get_block(num)
                    for num in block_numbers
                }

                for log in batch:
                    try:
                        block = blocks[log['blockNumber']]
                        event_sig = log['topics'][0].hex(
                        ) if log['topics'] else None

                        events.append({
                            'event_type': event_signatures.get(event_sig, "Unknown"),
                            'transaction_hash': log['transactionHash'].hex(),
                            'block_number': log['blockNumber'],
                            'timestamp': block['timestamp'],
                            'topics': [t.hex() for t in log['topics']],
                            'data': log['data']
                        })
                    except Exception as e:
                        logger.error("event_processing_error",
                                     error=str(e),
                                     block=log['blockNumber'])
                        continue

            # Sort events by timestamp
            events.sort(key=lambda x: x['timestamp'])

            return {
                'total_events': len(events),
                'events': events,
                'event_types': list(set(e['event_type'] for e in events)),
                'time_range': {
                    'from': events[0]['timestamp'] if events else None,
                    'to': events[-1]['timestamp'] if events else None
                }
            }

        except Exception as e:
            logger.error("event_fetch_error", error=str(e))
            return {
                'total_events': 0,
                'events': [],
                'event_types': [],
                'error': str(e)
            }

    def _analyze_volume_patterns(self, transactions):
        """Analyze transaction volume patterns"""
        if not transactions:
            return {"status": "no_transactions"}

        volumes = [tx['value'] for tx in transactions]
        timestamps = [tx['timestamp'] for tx in transactions]

        return {
            "total_volume": sum(volumes),
            "average_volume": sum(volumes) / len(volumes),
            "max_volume": max(volumes),
            "transaction_frequency": len(transactions) / (max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0,
            "volume_distribution": {
                "high_value_ratio": len([v for v in volumes if v > 0]) / len(volumes),
                "zero_value_ratio": len([v for v in volumes if v == 0]) / len(volumes)
            }
        }

    def _analyze_interaction_patterns(self, transactions):
        """Analyze contract interaction patterns"""
        if not transactions:
            return {"status": "no_transactions"}

        unique_senders = set(tx['from'] for tx in transactions)
        unique_receivers = set(tx['to'] for tx in transactions if tx['to'])
        method_counts = {}

        for tx in transactions:
            if tx.get('method_id'):
                method_counts[tx['method_id']] = method_counts.get(
                    tx['method_id'], 0) + 1

        return {
            "unique_addresses": {
                "senders": len(unique_senders),
                "receivers": len(unique_receivers)
            },
            "method_distribution": {
                method: count/len(transactions)
                for method, count in method_counts.items()
            },
            "interaction_frequency": {
                "total_interactions": len(transactions),
                "unique_interactors": len(unique_senders.union(unique_receivers))
            }
        }

    def _analyze_event_patterns(self, events):
        """Analyze event patterns and frequencies"""
        if not events:
            return {"status": "no_events"}

        event_types = {}
        timestamps = [event['timestamp'] for event in events]

        for event in events:
            event_type = event['event_type']
            event_types[event_type] = event_types.get(event_type, 0) + 1

        return {
            "event_distribution": {
                event_type: count/len(events)
                for event_type, count in event_types.items()
            },
            "event_frequency": len(events) / (max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0,
            "most_common_events": sorted(
                event_types.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]  # Top 5 most common events
        }

    def _calculate_risk_indicators(self, transactions, events):
        """Calculate risk indicators based on patterns"""
        risk_indicators = {
            "high_value_transactions": False,
            "unusual_method_patterns": False,
            "suspicious_events": False,
            "centralization_risk": False
        }

        # Check for high value transactions
        if transactions:
            volumes = [tx['value'] for tx in transactions]
            avg_volume = sum(volumes) / len(volumes)
            if any(v > avg_volume * 10 for v in volumes):
                risk_indicators["high_value_transactions"] = True

        # Check method patterns
        method_counts = {}
        for tx in transactions:
            if tx.get('method_id'):
                method_counts[tx['method_id']] = method_counts.get(
                    tx['method_id'], 0) + 1

        if method_counts:
            most_common_method_ratio = max(
                method_counts.values()) / len(transactions)
            if most_common_method_ratio > 0.8:  # 80% same method
                risk_indicators["unusual_method_patterns"] = True

        # Check for suspicious events
        suspicious_event_types = {
            "OwnershipTransferred", "Paused", "Blacklisted"}
        if events:
            event_types = {event['event_type'] for event in events}
            if suspicious_event_types.intersection(event_types):
                risk_indicators["suspicious_events"] = True

        # Check for centralization
        if transactions:
            unique_addresses = set(tx['from'] for tx in transactions).union(
                set(tx['to'] for tx in transactions if tx['to'])
            )
            if len(unique_addresses) < 5:  # Very few unique addresses
                risk_indicators["centralization_risk"] = True

        return risk_indicators

    def _calculate_risk_score(self, risk_indicators):
        """Calculate overall risk score"""
        risk_weights = {
            "high_value_transactions": 25,
            "unusual_method_patterns": 20,
            "suspicious_events": 30,
            "centralization_risk": 25
        }

        score = sum(
            risk_weights[indicator]
            for indicator, is_risky in risk_indicators.items()
            if is_risky
        )

        return {
            "score": score,
            "level": "HIGH" if score > 70 else "MEDIUM" if score > 30 else "LOW",
            "contributing_factors": [
                indicator for indicator, is_risky in risk_indicators.items()
                if is_risky
            ]
        }

    def _process_analysis_results(self, contract_address: str, results: List, depth: str, config: Dict) -> Dict:
        """Process analysis results based on depth and configuration"""
        try:
            base_result = {
                "contract_address": contract_address,
                "analysis_config": config,
                "timestamp": int(time.time())
            }

            # Filter out exceptions from results
            valid_results = [
                r for r in results
                if not isinstance(r, Exception)
            ]

            if depth == "quick":
                return {
                    **base_result,
                    "basic_metrics": self._get_basic_metrics(valid_results),
                    "risk_level": self._quick_risk_assessment(valid_results)
                }
            elif depth == "deep":
                return {
                    **base_result,
                    "detailed_metrics": self._get_detailed_metrics(valid_results),
                    "patterns": self._analyze_all_patterns(valid_results),
                    "risk_assessment": self._comprehensive_risk_analysis(valid_results)
                }
            else:  # standard
                return {
                    **base_result,
                    "metrics": self._get_standard_metrics(valid_results),
                    "risk_assessment": self._standard_risk_analysis(valid_results)
                }
        except Exception as e:
            logger.error("process_results_error",
                         error=str(e),
                         contract=contract_address,
                         depth=depth)
            return {
                **base_result,
                "error": str(e),
                "status": "failed"
            }

    async def _get_governance_history(self, contract_address: str) -> Dict:
        """Get governance-related events and changes"""
        try:
            # Common governance event signatures
            governance_signatures = {
                "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0": "OwnershipTransferred",
                "0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff": "RoleGranted",
                "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b": "RoleRevoked"
            }

            latest_block = await self.w3.eth.block_number
            from_block = max(0, latest_block - 10000)  # Look back ~1.5 days

            logs = await self.w3.eth.get_logs({
                'address': contract_address,
                'fromBlock': from_block,
                'toBlock': 'latest',
                'topics': [[sig for sig in governance_signatures.keys()]]
            })

            governance_events = []
            for log in logs:
                event_sig = log['topics'][0].hex()
                governance_events.append({
                    'type': governance_signatures.get(event_sig, "Unknown"),
                    'transaction_hash': log['transactionHash'].hex(),
                    'block_number': log['blockNumber'],
                    'data': log['data']
                })

            return {
                "total_events": len(governance_events),
                "events": governance_events,
                "recent_changes": len([e for e in governance_events if e['block_number'] > latest_block - 1000])
            }
        except Exception as e:
            logger.error("governance_history_error", error=str(e))
            return {"error": str(e)}

    def _get_basic_metrics(self, results: List) -> Dict:
        """Process basic metrics from analysis results"""
        try:
            transactions = results[0] if isinstance(results[0], list) else []
            events = results[1] if isinstance(results[1], list) else []

            return {
                "transaction_count": len(transactions),
                "event_count": len(events),
                "unique_addresses": len(set(tx['from'] for tx in transactions)),
                "last_activity": max([tx['timestamp'] for tx in transactions]) if transactions else None
            }
        except Exception as e:
            logger.error("basic_metrics_error", error=str(e))
            return {}

    def _get_detailed_metrics(self, results: List) -> Dict:
        """Process detailed metrics from analysis results"""
        try:
            transactions = results[0] if isinstance(results[0], list) else []
            events = results[1] if isinstance(results[1], list) else []
            holders = results[2] if len(results) > 2 and isinstance(
                results[2], dict) else {}

            return {
                "transactions": self._analyze_volume_patterns(transactions),
                "events": self._analyze_event_patterns(events),
                "holders": holders,
                "risk_indicators": self._calculate_risk_indicators(transactions, events)
            }
        except Exception as e:
            logger.error("detailed_metrics_error", error=str(e))
            return {}

    def _get_standard_metrics(self, results: List) -> Dict:
        """Process standard metrics from analysis results"""
        try:
            basic = self._get_basic_metrics(results)
            risk = self._calculate_risk_indicators(
                results[0] if isinstance(results[0], list) else [],
                results[1] if isinstance(results[1], list) else []
            )
            return {**basic, "risk_indicators": risk}
        except Exception as e:
            logger.error("standard_metrics_error", error=str(e))
            return {}

    def _quick_risk_assessment(self, results: List) -> Dict:
        """Quick risk assessment based on basic metrics"""
        try:
            transactions = results[0] if isinstance(results[0], list) else []
            events = results[1] if isinstance(results[1], list) else []

            risk_level = "LOW"
            if len(transactions) > 100 or len(events) > 50:
                risk_level = "MEDIUM"
            if any(tx['value'] > 1e18 for tx in transactions):  # > 1 ETH
                risk_level = "HIGH"

            return {"level": risk_level}
        except Exception as e:
            logger.error("quick_risk_assessment_error", error=str(e))
            return {"level": "UNKNOWN"}

    def _analyze_all_patterns(self, results: List) -> Dict:
        """Analyze all patterns in the data"""
        try:
            transactions = results[0] if isinstance(results[0], list) else []
            events = results[1] if isinstance(results[1], list) else []

            return {
                "volume": self._analyze_volume_patterns(transactions),
                "interactions": self._analyze_interaction_patterns(transactions),
                "events": self._analyze_event_patterns(events)
            }
        except Exception as e:
            logger.error("pattern_analysis_error", error=str(e))
            return {}

    def _comprehensive_risk_analysis(self, results: List) -> Dict:
        """Comprehensive risk analysis using all available data"""
        try:
            risk_indicators = self._calculate_risk_indicators(
                results[0] if isinstance(results[0], list) else [],
                results[1] if isinstance(results[1], list) else []
            )
            return self._calculate_risk_score(risk_indicators)
        except Exception as e:
            logger.error("comprehensive_risk_analysis_error", error=str(e))
            return {"level": "UNKNOWN"}

    def _standard_risk_analysis(self, results: List) -> Dict:
        """Standard risk analysis with balanced depth"""
        try:
            return self._quick_risk_assessment(results)
        except Exception as e:
            logger.error("standard_risk_analysis_error", error=str(e))
            return {"level": "UNKNOWN"}

    # Add missing helper methods
    def _get_risk_level(self, score: float) -> str:
        if score >= 70:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        return "LOW"

    def _identify_risk_factors(self, risk_scores: Dict) -> List[str]:
        return [factor for factor, score in risk_scores.items() if score > 50]

    def _generate_risk_recommendations(self, risk_scores: Dict) -> List[str]:
        recommendations = []
        if risk_scores.get("volume_patterns", 0) > 50:
            recommendations.append("Monitor large volume transactions closely")
        if risk_scores.get("holder_concentration", 0) > 50:
            recommendations.append("High holder concentration detected")
        if risk_scores.get("governance_risk", 0) > 50:
            recommendations.append("Review recent governance changes")
        return recommendations

    def _calculate_volume_risk(self, transactions: List) -> float:
        if not transactions:
            return 0
        total_value = sum(tx.get('value', 0) for tx in transactions)
        avg_value = total_value / len(transactions)
        high_value_txs = sum(1 for tx in transactions if tx.get(
            'value', 0) > avg_value * 2)
        return min(100, (high_value_txs / len(transactions)) * 100)

    def _calculate_interaction_risk(self, transactions: List) -> float:
        if not transactions:
            return 0
        unique_addresses = len(set(tx.get('from') for tx in transactions))
        return min(100, (1 - (unique_addresses / len(transactions))) * 100)

    def _calculate_concentration_risk(self, holders: Dict) -> float:
        if not holders or 'top_holders' not in holders:
            return 0
        top_holders = holders['top_holders'][:3]  # Top 3 holders
        total_balance = sum(balance for _, balance in holders.get(
            'balance_distribution', {}).items())
        if total_balance == 0:
            return 0
        concentration = sum(
            balance for _, balance in top_holders) / total_balance
        return min(100, concentration * 100)

    def _calculate_governance_risk(self, governance_events: List) -> float:
        if not governance_events:
            return 0
        recent_changes = governance_events.get('recent_changes', 0)
        return min(100, recent_changes * 20)  # 20 points per recent change

    def _calculate_security_event_risk(self, security_events: Dict) -> float:
        if not security_events:
            return 0
        total_events = security_events.get('total_events', 0)
        return min(100, total_events * 10)  # 10 points per security event
