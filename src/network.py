import threading, ipaddress, requests, sqlite3, socket, random, base64, struct, uuid, time, yaml, json, stun
from flask import Flask, render_template, request
from settings import Settings

import traceback

settings = Settings()

from logging import getLogger, config
logger = getLogger(__name__ )
config.dictConfig(yaml.load(open("config/logging.yaml").read(), Loader=yaml.SafeLoader))

conn = sqlite3.connect("dbs/yasChats.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS chats (
        uuid TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
""")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        uuid TEXT PRIMARY KEY,
        chatUuid TEXT NOT NULL,
        name TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
""")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS peers (
        uuid TEXT PRIMARY KEY,
        stunIp TEXT NOT NULL,
        stunPort INTEGER NOT NULL,
        natConeType TEXT NOT NULL,
        isLocalIp INTEGER NOT NULL
    )
""")
conn.commit()

onceConnectedIps = []
onceConnectedIpsLock = threading.Lock()

stunInfo = {"natConeType":"", "stunIp":"", "stunPort":None}

class Utils:
    def removeDuplicates(dicts:list[dict], key:str):
        seen = {}
        for d in dicts:
            seen[d[key]] = d
        return list(seen.values())
    def checkAndMergeStunDatas(newPeerDs:list[dict]):
        okNewPeerDs:list[dict] = Utils.removeDuplicates(newPeerDs, "stunIp")
        for newPeerD in okNewPeerDs:
            print(newPeerD["stunIp"])
            if Utils.isMyIp(newPeerD["stunIp"]):
                continue
            elif not (newPeerD["natConeType"] in ["Restricted Cone", "Full Cone"] or Utils.isLocalIp(newPeerD["stunIp"])):
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(6)
                try:
                    message = {
                        "m":"p"
                    }
                    sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")),(newPeerD["stunIp"], newPeerD["stunPort"]))
                    res = sock.recvfrom(1024)[0]
                    res = json.loads(base64.b64decode(res))
                    if not (res["m"] == "R" and res["r"] == 0):
                        continue
                except Exception as e:
                    logger.error(f"Error in checkAndMergeStunDatas:{e}")
                    continue
                cursor.execute("DELETE FROM peers WHERE stunIp=?", (newPeerD["stunIp"],))
                conn.commit()
                cursor.execute("INSERT INTO peers (uuid, stunIp, stunPort, natConeType, isLocalIp) VALUES (?, ?, ?, ?, ?)",(str(uuid.uuid4()), newPeerD["stunIp"], newPeerD["stunPort"], newPeerD["natConeType"], 1 if Utils.isLocalIp(newPeerD["stunIp"]) else 0))
                conn.commit()
    def isPortAvailable(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex(("127.0.0.1", port))
            return result != 0
    def checkPorts(x, y):
        for port in range(x, y+1):
            if Utils.isPortAvailable(port):
                return True
            else:
                return False
    def getStun(ip:str, port:int, sourcePort):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            localIp = sock.getsockname()[0]
            sock.close()
            natType, stunIp, stunPort = stun.get_ip_info(source_ip=localIp, source_port=sourcePort, stun_host=ip, stun_port=port)
            print(f"{natType} - {stunIp}:{stunPort}")
            return natType, stunIp, stunPort
        except Exception as e:
            logger.error(f"Exception(get STUN): {e}")
        return None, None, None
    def checkConnection(stunIp, stunPort):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(6)
            try:
                message = {
                    "m":"p"
                }
                sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")),
                            (stunIp, stunPort))
                res = sock.recvfrom(1024)[0]
                res = json.loads(base64.b64decode(res))
                if not (res["m"] == "R" and res["r"] == 0):
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
    def getPublicIp():
        res = requests.get("https://api.ipify.org")
        return res.text
    def getLocalIp():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        localIp = sock.getsockname()[0]
        sock.close()
        return localIp
    def isMyIp(ip):
        myPublicIp = Utils.getPublicIp()
        myLocalIp = Utils.getLocalIp()
        return ip == myPublicIp or ip == myLocalIp

class Server:
    def reqChatsList(addr, maxChatsLength:int):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            cursor.execute("SELECT * FROM chats")
            chats = cursor.fetchall()
            chatsDs:list[dict] = []
            for peer in random.sample(chats, min(len(chats), maxChatsLength)):
                chatsDs.append({"stunIp": peer[1], "stunPort": peer[2], "natConeType": peer[3]})
            message = {
                "m":"R",
                "r":0,
                "c":{
                    "chats":random.sample(chatsDs, min(len(chatsDs), maxChatsLength))
                }
            }
            sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")), addr)
    def reqMessagesList(addr, chatUuid:str):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            cursor.execute("SELECT * FROM messages WHERE chatUuid=?", (chatUuid,))
            messages = cursor.fetchall()
            messagesDs:list[dict] = [{"uuid":message[0], "name":message[2], "timestamp":message[3]} for message in messages]
            message = {
                "m":"R",
                "r":0,
                "c":{
                    "messages":messagesDs
                }
            }
            message = json.dumps(message).encode("utf-8")
            chunkSize = 2 * 1024 * 1024
            for i in range(0, len(message), chunkSize):
                chunk = message[i:i + chunkSize]
                packet = struct.pack("!I", len(chunk)) + chunk
                sock.sendto(base64.b64encode(packet), addr)
    def reqPeersList(addr, maxPeersLength:int):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            cursor.execute("SELECT * FROM peers")
            peers = cursor.fetchall()
            peersDs:list[dict] = []
            isLocalIp = Utils.isLocalIp(addr[0])
            for peer in random.sample(peers, min(len(peers), maxPeersLength)):
                if peer[4]:
                    if not isLocalIp:
                        continue
                peersDs.append({"stunIp": peer[1], "stunPort": peer[2], "natConeType": peer[3]})
            message = {
                "m":"R",
                "r":0,
                "c":{
                    "peers":random.sample(peersDs, min(len(peersDs), maxPeersLength))
                }
            }
            sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")), addr)
    def registerPeer(addr, peerData):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            stunIp = peerData["stunIp"]
            stunPort = peerData["stunPort"]
            natConeType = peerData["natConeType"]
            isLocalIp = Utils.isLocalIp(addr[0])
            if stunIp and stunPort and natConeType:
                if addr[0] != peerData["stunIp"] or isLocalIp:
                    stunIp = addr[0]
                if Utils.checkConnection(stunIp, stunPort):
                    uuidValue = str(uuid.uuid4())
                    cursor.execute("INSERT INTO peers (uuid, stunIp, stunPort, natConeType) VALUES (?, ?, ?, ?)",(uuidValue, stunIp, stunPort, natConeType))
                    conn.commit()
                    message = {
                        "m": "R",
                        "r": 0,
                        "c": {}
                    }
                    sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")), addr)
                    logger.info(f"Registered peer: {stunIp}:{stunPort}")
                else:
                    logger.warning(f"Failed to connect to peer: {stunIp}:{stunPort}")
                    message = {
                        "m": "R",
                        "r": 3,
                        "c": {}
                    }
                    sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")), addr)

class Client:
    def getChatsFromPeers(ip:str, port:int, maxChats=20):
        chats = {}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                message = {
                    "m":"r",
                    "t":"g",
                    "d":"c",
                    "a":{
                        "maxChatsLength":maxChats,
                    }
                }
                sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")), (ip, port))
                res, addr = sock.recvfrom(200*maxChats+120)
                res = json.loads(base64.b64decode(res))
                if res["m"] == "R" and res["r"] == "0":
                    chats[addr[0]] = res["c"]["chats"]
                    logger.debug(f"Get chats From:{addr[0]}")
                else:
                    logger.warning(f"Failed get chats From:{addr[0]}")
                    return None
            except Exception as e:
                logger.error(f"Exception(get chats):{e}")
                return None
        return chats
    def getMessagesFromPeer(ip:str, port:int, chatUuid:str):
        messages = {}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(6)
            try:
                message = {
                    "m":"r",
                    "t":"g",
                    "d":"m",
                    "a":{
                        "chatUuid":chatUuid
                    }
                }
                sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")), (ip, port))
                fullRes = b""
                while True:
                    try:
                        res, addr = sock.recvfrom(1024)
                        fullRes += base64.b64decode(res)
                        if len(fullRes) >= 4:
                            messageSize = struct.unpack("!I", fullRes[:4])[0]
                            if len(fullRes) >= messageSize + 4:
                                break
                    except socket.timeout:
                        logger.error(f"Timeout waiting for response from {addr[0]}")
                        return None
                res = json.loads(fullRes[4:])
                if res["m"] == "R" and res["r"] == "0":
                    messages[addr[0]] = res["c"]["messages"]
                    logger.debug(f"Get messages from:{addr[0]}")
            except Exception as e:
                logger.error(f"Exception(get messages):{e}")
                return None
        return messages
    def getPeers(ip:str, port:int, maxPeers=20):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(6)
            message = {
                "m":"g",
                "t":"r",
                "d":"i",
                "a":{
                    "maxPeersLength":maxPeers
                }
            }
            sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")), (ip, port))
            try:
                res = sock.recvfrom(130*maxPeers+120)[0]
                res = json.loads(base64.b64decode(res.decode("utf-8")))
                print(res)
                if res["m"] == "R" and res["r"] == 0:
                    Utils.checkAndMergeStunDatas(res["c"]["peers"])
                    logger.debug(f"Get peers From:{ip}")
                else:
                    logger.warning(f"Failed get peers From:{ip}")
            except Exception as e:
                print(traceback.format_exc())
                logger.error(f"Exception(get peers):{e}")
    def registerPeer(ip:str, port:int):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(6)
            natConeType = stunInfo["natConeType"]
            stunIp = stunInfo["stunIp"]
            stunPort = stunInfo["stunPort"]
            sourcePort = stunInfo["sourcePort"]
            if natConeType not in ["Restricted Cone", "Full Cone"]:
                return False
            message = {
                "m":"r",
                "t":"r",
                "d":"i",
                "a":{
                    "natConeType":natConeType,
                    "stunIp":stunIp,
                    "stunPort":stunPort,
                    "sourcePort":sourcePort
                }
            }
            sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")), (ip, port))
            try:
                res = sock.recvfrom(1024)[0]
                res = json.loads(base64.b64decode(res))
                if res["m"] == "R" and res["r"] == 0:
                    logger.info(f"Register I:{stunIp}:{stunPort}")
            except Exception as e:
                logger.error(f"Exception during registration:{e}")
                return False
        return True

class Peer:
    def __init__(self):
        pass
    def listenForMessages(self):
        sourcePort = stunInfo["sourcePort"]
        logger.debug(f"Start Listen - 0.0.0.0:{sourcePort}")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("0.0.0.0", sourcePort))
            while True:
                res, addr = sock.recvfrom(1024)
                res = json.loads(base64.b64decode(res))
                threading.Thread(target=self.handleMessage, args=(res, addr), daemon=True).start()
    def handleMessage(self, message:dict, addr):
        with onceConnectedIpsLock:
            onceConnectedIps.append(addr[0])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(6)
            try:
                if message["m"] == "p":
                    response = {
                        "m":"R",
                        "r":0,
                        "c":{}
                    }
                    sock.sendto(base64.b64encode(json.dumps(response).encode("utf-8")), addr)
                if message["m"] == "r":
                    if message["t"] == "g":
                        if message["d"] == "c":
                            Server.reqChatsList(addr, message["a"]["maxChatsLength"])
                        elif message["d"] == "m":
                            Server.reqMessagesList(addr, message["a"]["chatUuid"])
                        elif message["d"] == "i":
                            Server.reqPeersList(addr, message["a"]["maxPeersLength"])
                    elif message["t"] == "r":
                        if message["d"] == "i":
                            Server.registerPeer(addr, message["a"])
                else:
                    message = {
                        "m":"R",
                        "r":2,
                        "c":{}
                    }
                    sock.sendto(base64.b64encode(json.dumps(message).encode("utf-8")), addr)
            except Exception as e:
                logger.error(f"Exception in handleMessage:{e}")
                response = {
                    "m":"R",
                    "r":1,
                    "c":{}
                }
                sock.sendto(base64.b64encode(json.dumps(response).encode("utf-8")), addr)
    def syncer(self):
        while True:
            cursor.execute("SELECT * FROM peers")
            peers = cursor.fetchall()
            print(peers)
            for server in settings.settings["bootstrapNodes"]:
                Client.getPeers(server["ip"], server["port"])
            for peer in peers:
                if peer[1] not in onceConnectedIps and peer[3] != "Full Cone":
                    logger.warning(f"I Dont Connect:{peer[1]}")
                    continue
                Client.getPeers(peer[1], peer[2])
            time.sleep(60)
    def start(self):
        for port in range(30000, 40001):
            if Utils.isPortAvailable(port):
                stunInfo["sourcePort"] = port
                randomStunServer = random.choice(settings.settings["stunServers"])
                natConeType, stunIp, stunPort = Utils.getStun(randomStunServer["ip"], randomStunServer["port"], port)
                if not (natConeType and stunIp and stunPort):
                    continue
                stunInfo["natConeType"] = natConeType
                stunInfo["stunIp"] = stunIp
                stunInfo["stunPort"] = stunPort
                break
        threading.Thread(target=self.listenForMessages).start()
        for server in settings.settings["bootstrapNodes"]:
            Client.registerPeer(server["ip"], server["port"])
            Client.getPeers(server["ip"], server["port"])
        self.syncer()

class Web():
    app = Flask(import_name="YasChat", template_folder="src/templates")
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    cursor = None
    def __init__(self, host="0.0.0.0", port=8080):
        self.host = host
        self.port = port
    @app.route('/')
    def index():
        return render_template("index.html")
    @app.route('/peerList')
    def peerList():
        cursor.execute("SELECT * FROM peers")
        peers = cursor.fetchall()
        return render_template("peerList.html", peers=peers)
    @app.route('/chatList')
    def chatList():
        chatList = []
        return render_template("chatList.html", chatList=chatList)
    @app.route('/newChat', methods=['POST', 'GET'])
    def newChat():
        if request.method == 'GET':
            return render_template("newChat.html")
    def runWeb(self):
        self.app.run(self.host, self.port)

def start():
    try:
        peer = Peer()
        web = Web()
        threading.Thread(target=peer.start, daemon=True).start()
        web.runWeb()

    except:
        conn.close()