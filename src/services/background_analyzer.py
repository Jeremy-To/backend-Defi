from dataclasses import dataclass
from typing import Dict, Optional
import asyncio
import time
import structlog
from web3 import AsyncWeb3
from cachetools import TTLCache

logger = structlog.get_logger()

@dataclass
class AnalysisTask:
    contract_address: str
    status: str  # 'pending', 'in_progress', 'completed', 'failed'
    start_time: float
    result: Optional[Dict] = None
    error: Optional[str] = None

class BackgroundAnalyzer:
    def __init__(self, w3: AsyncWeb3):
        self.w3 = w3
        self._tasks: Dict[str, AnalysisTask] = {}
        self._cache = TTLCache(maxsize=100, ttl=3600)  # 1 hour cache
        self._analysis_queue = asyncio.Queue()
        self._worker_task = None

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

    async def queue_analysis(self, contract_address: str) -> str:
        """Queue a contract for detailed analysis"""
        task_id = f"analysis_{contract_address}_{int(time.time())}"
        self._tasks[task_id] = AnalysisTask(
            contract_address=contract_address,
            status="pending",
            start_time=time.time()
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
                           task_id=task_id)
                
                task.status = "in_progress"
                
                try:
                    # Perform detailed analysis
                    result = await self._perform_detailed_analysis(task.contract_address)
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
                
                finally:
                    self._analysis_queue.task_done()
                    
            except Exception as e:
                logger.error("worker_error", error=str(e))
                await asyncio.sleep(1)  # Prevent tight loop on errors

    async def _perform_detailed_analysis(self, contract_address: str) -> Dict:
        """Perform comprehensive contract analysis"""
        latest_block = await self.w3.eth.block_number
        # Analyze last 1000 blocks (~ 3-4 hours)
        from_block = max(0, latest_block - 1000)

        # Collect detailed data
        transactions = await self._get_detailed_transactions(
            contract_address, from_block, latest_block)
        events = await self._get_detailed_events(
            contract_address, from_block, latest_block)
        
        # Analyze patterns
        volume_analysis = self._analyze_volume_patterns(transactions)
        interaction_analysis = self._analyze_interaction_patterns(transactions)
        event_analysis = self._analyze_event_patterns(events)
        risk_indicators = self._calculate_risk_indicators(
            transactions, events)

        return {
            "contract_address": contract_address,
            "analysis_period": {
                "from_block": from_block,
                "to_block": latest_block,
                "block_range": latest_block - from_block
            },
            "transaction_analysis": {
                "total_transactions": len(transactions),
                "volume_patterns": volume_analysis,
                "interaction_patterns": interaction_analysis
            },
            "event_analysis": event_analysis,
            "risk_assessment": {
                "indicators": risk_indicators,
                "overall_risk_score": self._calculate_risk_score(risk_indicators)
            },
            "timestamp": int(time.time())
        }

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
                           (tx.get('from') and tx['from'].lower() == contract_address.lower())
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
        """Get and decode contract events"""
        events = []
        try:
            # Common event signatures
            event_signatures = {
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer",
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": "Approval",
                "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31": "OwnershipTransferred",
            }

            logs = await self.w3.eth.get_logs({
                'address': contract_address,
                'fromBlock': from_block,
                'toBlock': to_block
            })

            for log in logs:
                block = await self.w3.eth.get_block(log['blockNumber'])
                event_sig = log['topics'][0].hex() if log['topics'] else None
                
                events.append({
                    'event_type': event_signatures.get(event_sig, "Unknown"),
                    'transaction_hash': log['transactionHash'].hex(),
                    'block_number': log['blockNumber'],
                    'timestamp': block['timestamp'],
                    'topics': [t.hex() for t in log['topics']],
                    'data': log['data']
                })

        except Exception as e:
            logger.error("event_fetch_error", error=str(e))

        return events

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
                method_counts[tx['method_id']] = method_counts.get(tx['method_id'], 0) + 1

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
                method_counts[tx['method_id']] = method_counts.get(tx['method_id'], 0) + 1
        
        if method_counts:
            most_common_method_ratio = max(method_counts.values()) / len(transactions)
            if most_common_method_ratio > 0.8:  # 80% same method
                risk_indicators["unusual_method_patterns"] = True

        # Check for suspicious events
        suspicious_event_types = {"OwnershipTransferred", "Paused", "Blacklisted"}
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