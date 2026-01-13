"""
Quick test script to verify Groq API key and debug the issue
"""
import requests
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv('GROQ_API_KEY')
print(f"API Key: {api_key[:15]}...")

# Test the API
url = "https://api.groq.com/openai/v1/chat/completions"
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

payload = {
    "model": "llama-3.1-70b-versatile",
    "messages": [
        {
            "role": "user",
            "content": "Say hello"
        }
    ],
    "temperature": 0.1,
    "max_tokens": 100
}

print("\nTesting Groq API...")
response = requests.post(url, headers=headers, json=payload)

print(f"Status Code: {response.status_code}")
print(f"Response: {response.text[:500]}")

if response.status_code == 200:
    print("\n✅ API key is valid!")
else:
    print("\n❌ API key test failed!")
    print(f"Full error: {response.text}")
