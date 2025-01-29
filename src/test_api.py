import requests
import json
import sys


def test_api():
    url = "http://localhost:8000/api/analyze-contract"

    # Test cases
    contracts = [
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"   # Uniswap V2 Router
    ]

    for contract in contracts:
        print(f"\nTesting contract: {contract}")
        try:
            response = requests.post(
                url,
                json={"contract_address": contract},
                timeout=30  # Add timeout
            )

            print(f"Response status: {response.status_code}")

            if response.status_code == 200:
                result = response.json()
                print("\nAnalysis Results:")
                print(f"Contract Address: {result['contract_address']}")
                print(f"Code Size: {result.get('code_size', 'N/A')} bytes")
                print(f"Risk Score: {result['risk_score']}")
                print("\nVulnerabilities Found:")
                for vuln in result['vulnerabilities']:
                    print(f"\nType: {vuln['type']}")
                    print(f"Severity: {vuln['severity']}")
                    print(f"Description: {vuln['description']}")
            else:
                print(f"Error: {response.status_code}")
                try:
                    error_detail = response.json()
                    print(f"Error details: {
                          json.dumps(error_detail, indent=2)}")
                except:
                    print(f"Raw response: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {str(e)}")
        except Exception as e:
            print(f"Unexpected error: {str(e)}")


if __name__ == "__main__":
    try:
        test_api()
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Test failed: {str(e)}")
        sys.exit(1)
