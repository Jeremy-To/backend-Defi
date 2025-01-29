import asyncio
from services.contract_analyzer import ContractAnalyzer
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()


async def test_contract_analysis():
    # Initialize analyzer
    analyzer = ContractAnalyzer(os.getenv("ETHEREUM_RPC_URL"))

    # Test cases with real Ethereum mainnet contracts
    test_cases = [
        {
            # Uniswap V2: Router 2
            "address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
            "description": "Uniswap Router - Reference Contract",
            "expected_issues": ["high_complexity"]
        },
        {
            # USDT (Known for centralization)
            "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "description": "USDT - Centralized Control",
            "expected_issues": ["centralized_control"]
        },
        {
            # SushiSwap: MasterChef
            "address": "0xc2EdaD668740f1aA35E4D8f227fB8E17dcA888Cd",
            "description": "SushiSwap MasterChef - Complex Permissions",
            "expected_issues": ["complex_permissions"]
        }
    ]

    for test_case in test_cases:
        print(f"\n{'='*50}")
        print(f"Testing {test_case['description']}")
        print(f"Address: {test_case['address']}")
        print(f"Expected Issues: {', '.join(test_case['expected_issues'])}")
        print(f"{'='*50}")

        try:
            result = await analyzer.analyze_contract(test_case['address'])

            # Print basic info
            print("\nBasic Information:")
            print(f"Contract Size: {result['code_size']} bytes")
            print(f"Risk Score: {result['risk_score']}")

            # Print vulnerabilities
            print("\nVulnerabilities Found:")
            if result['vulnerabilities']:
                for vuln in result['vulnerabilities']:
                    print(f"\nType: {vuln['type']}")
                    print(f"Severity: {vuln['severity']}")
                    print(f"Description: {vuln['description']}")
                    if vuln['evidence']:
                        print(f"Evidence: {vuln['evidence']}")
            else:
                print("No vulnerabilities detected")

            # Print transaction summary
            print("\nTransaction Summary:")
            tx_summary = result['transaction_summary']
            for key, value in tx_summary.items():
                print(f"{key.replace('_', ' ').title()}: {value}")

            # Print holder statistics
            print("\nHolder Statistics:")
            holder_stats = result['holder_stats']
            for key, value in holder_stats.items():
                print(f"{key.replace('_', ' ').title()}: {value}")

            # Print timestamp
            print(f"\nAnalysis Time: {
                datetime.fromtimestamp(result['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")

        except Exception as e:
            print(f"Error analyzing contract: {str(e)}")


def print_separator():
    print("\n" + "="*50 + "\n")


if __name__ == "__main__":
    print("Starting Contract Security Analysis...")
    print_separator()
    asyncio.run(test_contract_analysis())
