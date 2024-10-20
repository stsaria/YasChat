import threading, ipaddress, sqlite3, socket, random, base64, json, uuid, yaml
from logging import getLogger, config

logger = getLogger(__name__)
config.dictConfig(yaml.load(open("config/logging.yaml").read(), Loader=yaml.SafeLoader))

conn = sqlite3.connect("dbs/bootstrapServer.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS peers (
        uuid TEXT PRIMARY KEY,
        stunIp TEXT NOT NULL,
        stunPort INTEGER NOT NULL,
        natConeType TEXT NOT NULL,
        isLocalIp INTEGER NOT NULL
    )
""")

class Utils:
    def checkConnection(stunIp, stunPort):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(6)
            try:
                message = {
                    "m":"p"
                }
                sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")),(stunIp, stunPort))
                message = sock.recvfrom(1024)[0]
                message = json.loads(base64.b64decode(message))
                if not (message["m"] == "R" and message["r"] == 0):
                    return False
            except:
                return False
        return True
    def isLocalIp(ipAddress):
        localIpv4 = [
            '127.0.0.1',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16'
        ]
        localIpv6 = [
            '::1',
            'fc00::/7',
            'fe80::/10'
        ]
        try:
            ip = ipaddress.ip_address(ipAddress)
            if isinstance(ip, ipaddress.IPv4Address):
                for local in localIpv4:
                    if '/' in local:
                        network = ipaddress.ip_network(local, strict=False)
                        if ip in network:
                            return True
                    elif ip == ipaddress.ip_address(local):
                        return True
            if isinstance(ip, ipaddress.IPv6Address):
                for local in localIpv6:
                    if '/' in local:
                        network = ipaddress.ip_network(local, strict=False)
                        if ip in network:
                            return True
                    elif ip == ipaddress.ip_address(local):
                        return True
        except ValueError:
            return False
        return False

class BootstrapServer:
    def __init__(self, host='0.0.0.0', port=9000):
        self.host = host
        self.port = port
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.serverSocket.bind((self.host, self.port))
        logger.info(f"Bootstrap server started at {self.host}:{self.port}")
    def handleRequest(self, message, addr):
        logger.debug(f"Received message from {addr}: {message}")
        if message.get("m") == "r" and message.get("t") == "r" and message.get("d") == "i":
            self.registerPeer(message["a"], addr)
        elif message.get("m") == "g" and message.get("t") == "r" and message.get("d") == "i":
            self.sendPeersList(addr, message["a"]["maxPeersLength"])
    def registerPeer(self, peerData, addr):
        stunIp = peerData.get("stunIp")
        stunPort = peerData.get("stunPort")
        natConeType = peerData.get("natConeType")
        sourcePort = peerData.get("sourcePort")
        isLocalIp = Utils.isLocalIp(addr[0])
        if stunIp and stunPort and natConeType and sourcePort:
            if addr[0] != peerData.get("stunIp") or isLocalIp:
                stunIp = addr[0]
                stunPort = sourcePort
            if Utils.checkConnection(stunIp, stunPort):
                uuidValue = str(uuid.uuid4())
                cursor.execute("DELETE FROM peers WHERE stunIp=?", (stunIp,))
                cursor.execute("INSERT INTO peers (uuid, stunIp, stunPort, natConeType, isLocalIp) VALUES (?, ?, ?, ?, ?)",(uuidValue, stunIp, stunPort, natConeType, 1 if isLocalIp else 0))
                conn.commit()
                message = {
                    "m": "R",
                    "r": 0,
                    "c": {}
                }
                self.sendResponse(message, addr)
                logger.info(f"Registered peer: {stunIp}:{stunPort}")
            else:
                logger.warning(f"Failed to connect to peer: {stunIp}:{stunPort}")
                message = {
                    "m": "R",
                    "r": 3,
                    "c": {}
                }
                self.sendResponse(message, addr)
    def sendPeersList(self, addr, maxPeersLength):
        cursor.execute("SELECT * FROM peers")
        peers = cursor.fetchall()
        peersData:list[dict] = []
        isLocalIp = Utils.isLocalIp(addr[0])
        for peer in random.sample(peers, min(len(peers), maxPeersLength)):
            if peer[4]:
                if not isLocalIp:
                    continue
            peersData.append({"stunIp": peer[1], "stunPort": peer[2], "natConeType": peer[3]})
        message = {
            "m": "R",
            "r": 0,
            "c": {"peers": peersData}
        }
        self.sendResponse(message, addr)
    def sendResponse(self, message, addr):
        responseEncoded = base64.b64encode(json.dumps(message).encode("utf-8"))
        self.serverSocket.sendto(responseEncoded, addr)
    def run(self):
        while True:
            try:
                data, addr = self.serverSocket.recvfrom(1024)
                message = json.loads(base64.b64decode(data))
                threading.Thread(target=self.handleRequest, args=(message, addr), daemon=True).start()
            except Exception as e:
                logger.error(f"Error while handling request: {e}")
    def loop(self):
        while True:
            try:
                pass
            except:
                return

if __name__ == "__main__":
    server = BootstrapServer()
    threading.Thread(target=server.run, daemon=True).start()
    server.loop()