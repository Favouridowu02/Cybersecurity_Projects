#!/usr/bin/python3
"""
"""
import requests

url = "http://127.0.0.1:21"
response = requests.get(url)
print(response.status_code)
print(response.text)