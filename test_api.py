import urllib.request
import json

req = urllib.request.Request("http://localhost:8080/api/search", method="POST")
req.add_header("Content-Type", "application/json")
data = json.dumps({"session_id": "3f710023-3c93-4c56-8783-d3870b87dcba", "query": ""}).encode("utf-8")

try:
    with urllib.request.urlopen(req, data=data) as f:
        res = json.loads(f.read().decode("utf-8"))
        for row in res.get("results", [])[:5]:
            print(f"Flow: {row.get('protocol')} - RTT: {row.get('avg_rtt_us')} - Bytes F: {row.get('fwd_bytes')}")
except Exception as e:
    print("Error:", e)
