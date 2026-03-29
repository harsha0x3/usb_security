import requests
import json
import time


def test_rate_limit(url, total_requests=60, delay=0):
    """
    Sends multiple requests to test rate limiting.

    Args:
        url (str): API endpoint
        total_requests (int): Number of requests to send
        delay (float): Delay between requests (seconds)
    """

    headers = {"Content-Type": "application/json"}

    payload = {
        "username": "offline_user",
        "action": "test_action",
        "usb_serial_hash": "abc123hash",
        "machine_id": "machine_001",
        "operation": "test_op",
        "status": "success",
        "files": "file1.txt,file2.txt",
    }

    success_count = 0
    rate_limited_count = 0
    other_errors = 0

    for i in range(total_requests):
        response = requests.post(url, headers=headers, data=json.dumps(payload))

        if response.status_code == 200:
            success_count += 1
        elif response.status_code == 429:
            rate_limited_count += 1
            print(f"[{i}] ❌ Rate limited (429)")
        else:
            other_errors += 1
            print(f"[{i}] ⚠️ Status: {response.status_code}, Response: {response.text}")

        if delay > 0:
            time.sleep(delay)

    print("\n=== Test Summary ===")
    print(f"Total Requests: {total_requests}")
    print(f"Success: {success_count}")
    print(f"Rate Limited (429): {rate_limited_count}")
    print(f"Other Errors: {other_errors}")


def test_cors(url):
    test_origin = "https://www.haiku.com"  # attacker-controlled origin

    headers = {"Origin": test_origin, "Content-Type": "application/json"}

    try:
        response = requests.post(
            url,
            headers=headers,
            json={"test": "data"},  # minimal payload
            timeout=10,
        )

        print(f"Status Code: {response.status_code}")

        acao = response.headers.get("Access-Control-Allow-Origin")
        acc = response.headers.get("Access-Control-Allow-Credentials")

        print(f"Access-Control-Allow-Origin: {acao}")
        print(f"Access-Control-Allow-Credentials: {acc}")

        # 🔍 Evaluation
        if response.status_code == 403:
            print("✅ GOOD: Request blocked (browser requests denied)")
        elif acao == test_origin:
            print("❌ VULNERABLE: Origin is reflected (CORS misconfiguration)")
        elif acao == "*":
            print("⚠️ WARNING: Wildcard CORS enabled")
        elif acao is None:
            print("✅ GOOD: No CORS headers present")
        else:
            print("⚠️ CHECK: Unexpected CORS behavior")

    except Exception as e:
        print(f"Error testing CORS: {e}")


# test_rate_limit("http://localhost:8054/sync/log", total_requests=70, delay=0)
test_cors("http://localhost:8054/get_excluded_extensions")
