from fastapi import FastAPI, HTTPException
import http.client
import json
import requests
from dotenv import load_dotenv
import os

app = FastAPI()
load_dotenv()

# QuillCheck API details
QUILLCHECK_API_URL = "check-api.quillai.network"
QUILLCHECK_API_KEY = os.getenv("QUILLCHECK_API_KEY")

# Coinbase API details (use actual product id like 'ETH-USD')
COINBASE_API_URL = "api.coinbase.com"
COINBASE_API_KEY = os.getenv("COINBASE_API_KEY")

@app.get("/detect-scam")
def detect_scam(contract_address: str, blockchain: str, coinbase_token_id: str):
    """
    Detect if a token is a scam by checking QuillCheck and Coinbase data.
    """
    try:
        # Step 1: Fetch token data from QuillCheck API
        # Set up the connection using http.client
        conn = http.client.HTTPSConnection(QUILLCHECK_API_URL)
        
        # Format the URL and parameters
        url = f"/api/v1/tokens/information/{contract_address}?chainId={blockchain}"
        
        # Set headers including the API key for QuillCheck
        headers = {
            'Content-Type': 'application/json',
            'x-api-key': QUILLCHECK_API_KEY
        }
        
        # Send the GET request to QuillCheck
        conn.request("GET", url, '', headers)
        res = conn.getresponse()
        data = res.read()
        
        # Decode and load the JSON response from QuillCheck
        token_data = json.loads(data.decode("utf-8"))
        
        # Step 2: Check QuillCheck honeypot detection
        honeypot = token_data.get("honeypot_detection", {}).get("is_honeypot", False)
        if honeypot:
            return {"risk_level": "High Risk", "message": "Honeypot detected!"}
        
        # Step 3: Fetch token price data from Coinbase API
        coinbase_url = f"/v2/prices/{coinbase_token_id}/spot"
        headers_coinbase = {
            'Authorization': f"Bearer {COINBASE_API_KEY}"
        }
        
        coinbase_response = requests.get(
            f"https://{COINBASE_API_URL}{coinbase_url}",
            headers=headers_coinbase
        )
        
        if coinbase_response.status_code == 200:
            coinbase_data = coinbase_response.json()
            coinbase_price = coinbase_data.get("data", {}).get("amount")
            if coinbase_price:
                return {"risk_level": "Low Risk", "message": f"Price on Coinbase: {coinbase_price} USD, Honeypot not detected!", }
            else:
                return {"risk_level": "Unknown Risk", "message": "Unable to fetch token price from Coinbase, Honeypot Detected!"}
        else:
            return {"risk_level": "Unknown Risk", "message": "Unable to fetch data from Coinbase, Honeypot Detected!"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))