1. #### In fl\_server.py (The Server):



* Line: uvicorn.run(app, host="0.0.0.0", port=8000)
* Do not change 0.0.0.0: This value tells the server to "listen on all network adapters." If you change this to a specific IP (like 192.168.1.5), the server might fail to start or block connections from other computers.
* Port: You can change 8000 to 5000 if you want, just make sure you update the client too.







#### 2\. In fl\_client.py (The Client):



* Line: SERVER\_URL = "http://localhost:8000"
* YES, Edit This: This is where you tell the client where to find the Master PC.
* Change to: SERVER\_URL = "http://192.168.1.XX:8000" (Replace 192.168.1.XX with your Master PC's actual LAN IP address).







#### Summary:



Server Code: Keep host="0.0.0.0".

Client Code: Change localhost to the Master PC's IP.

