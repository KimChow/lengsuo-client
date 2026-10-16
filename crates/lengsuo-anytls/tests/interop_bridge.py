import ssl, socket, threading, sys
port = int(sys.argv[1])
upstream = int(sys.argv[2])
LOG = open(f"/tmp/bridge-{port}.log", "w")
def log(msg):
    LOG.write(msg + chr(10))
    LOG.flush()
front = socket.socket()
front.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
front.bind(("127.0.0.1", port))
front.listen(4)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
def pump(a, b, tag):
    first = True
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            if first:
                log(f"bridge[{tag}] first bytes: " + data[:8].hex())
                first = False
            b.sendall(data)
    except OSError:
        pass
while True:
    raw, _ = front.accept()
    try:
        up_raw = socket.create_connection(("127.0.0.1", upstream))
        tls = ctx.wrap_socket(up_raw, server_hostname="localhost")
    except Exception as exc:
        log("bridge error: " + repr(exc))
        try:
            raw.close()
        except OSError:
            pass
        continue
    threading.Thread(target=pump, args=(tls, raw, "srv-to-client"), daemon=True).start()
    threading.Thread(target=pump, args=(raw, tls, "client-to-srv"), daemon=True).start()
