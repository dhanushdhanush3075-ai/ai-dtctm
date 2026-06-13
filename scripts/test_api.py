"""
AI-DTCTM | Quick API Test Script
Test the FastAPI server endpoints
"""

import requests
import json

BASE_URL = "http://localhost:8000"

print("="*80)
print("AI-DTCTM | API TEST SCRIPT")
print("="*80)
print()

# Test 1: Health check
print("[TEST 1] Health Check")
try:
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    print()
except Exception as e:
    print(f"Error: {e}")
    print()

# Test 2: Get token
print("[TEST 2] Get Access Token")
try:
    response = requests.post(f"{BASE_URL}/api/v1/auth/token?api_key=test-key-123")
    print(f"Status: {response.status_code}")
    token = response.json()["access_token"]
    print(f"Token: {token[:50]}...")
    print()
except Exception as e:
    print(f"Error: {e}")
    print()

# Test 3: System status
print("[TEST 3] System Status (requires token)")
try:
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/v1/status", headers=headers)
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    print()
except Exception as e:
    print(f"Error: {e}")
    print()

# Test 4: Scan URL
print("[TEST 4] Scan URL")
try:
    headers = {"Authorization": f"Bearer {token}"}
    data = {"url": "https://paypal-verify.com"}
    response = requests.post(f"{BASE_URL}/api/v1/scan/url", json=data, headers=headers)
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    print()
except Exception as e:
    print(f"Error: {e}")
    print()

# Test 5: Get analytics
print("[TEST 5] Get Analytics")
try:
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/v1/analytics/kpi", headers=headers)
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    print()
except Exception as e:
    print(f"Error: {e}")
    print()

print("="*80)
print("[INFO] All tests completed!")
print("="*80)
