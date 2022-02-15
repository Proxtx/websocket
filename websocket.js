import crypto from "crypto";

class Socket {
  socket;
  message = [];
  disconnect = [];

  constructor(socket) {
    this.socket = socket;
    socket.on("data", (buffer) => {
      const message = parseMessage(buffer);
      if (message) {
        for (let callback of this.message) {
          callback(message);
        }
      } else if (message === null) {
        for (let callback of this.disconnect) {
          callback();
        }
      }
    });
  }

  onMessage = (callback) => {
    this.message.push(callback);
  };

  onDisconnect = (callback) => {
    this.disconnect.push(callback);
  };

  send = (message) => {
    this.socket.write(constructReply(message));
  };
}

export class WebSocket {
  sockets = [];
  connect = [];

  constructor(server) {
    server.on("upgrade", (req, socket) => {
      if (req.headers.upgrade !== "websocket") {
        socket.end("HTTP/1.1 400 Bad Request");
        return;
      }
      const acceptKey = req.headers["sec-websocket-key"];
      const hash = generateAcceptValue(acceptKey);
      const responseHeaders = [
        "HTTP/1.1 101 Web Socket Protocol Handshake",
        "Upgrade: WebSocket",
        "Connection: Upgrade",
        `Sec-WebSocket-Accept: ${hash}`,
      ];
      socket.write(responseHeaders.join("\r\n") + "\r\n\r\n");

      let returnSocket = new Socket(socket);
      this.sockets.push(returnSocket);
      for (let callback of this.connect) {
        callback(returnSocket);
      }
    });
  }

  onConnect = (callback) => {
    this.connect.push(callback);
  };
}

const constructReply = (data) => {
  const json = typeof data == "string" ? data : JSON.stringify(data);
  const jsonByteLength = Buffer.byteLength(json);
  const lengthByteCount = jsonByteLength < 126 ? 0 : 2;
  const payloadLength = lengthByteCount === 0 ? jsonByteLength : 126;
  const buffer = Buffer.alloc(2 + lengthByteCount + jsonByteLength);
  buffer.writeUInt8(0b10000001, 0);
  buffer.writeUInt8(payloadLength, 1);
  let payloadOffset = 2;
  if (lengthByteCount > 0) {
    buffer.writeUInt16BE(jsonByteLength, 2);
    payloadOffset += lengthByteCount;
  }
  buffer.write(json, payloadOffset);
  return buffer;
};

const generateAcceptValue = (acceptKey) => {
  return crypto
    .createHash("sha1")
    .update(acceptKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", "binary")
    .digest("base64");
};

const parseMessage = (buffer) => {
  const firstByte = buffer.readUInt8(0);
  const opCode = firstByte & 0xf;
  if (opCode === 0x8) return null;
  if (opCode !== 0x1) return;
  const secondByte = buffer.readUInt8(1);
  const isMasked = Boolean((secondByte >>> 7) & 0x1);
  let currentOffset = 2;
  let payloadLength = secondByte & 0x7f;
  if (payloadLength > 125) {
    if (payloadLength === 126) {
      payloadLength = buffer.readUInt16BE(currentOffset);
      currentOffset += 2;
    } else {
      throw new Error("Large payloads not currently implemented");
    }
  }

  let maskingKey;
  if (isMasked) {
    maskingKey = buffer.readUInt32BE(currentOffset);
    currentOffset += 4;
  }

  const data = Buffer.alloc(payloadLength);
  if (isMasked) {
    for (let i = 0, j = 0; i < payloadLength; ++i, j = i % 4) {
      const shift = j === 3 ? 0 : (3 - j) << 3;
      const mask = (shift === 0 ? maskingKey : maskingKey >>> shift) & 0xff;
      const source = buffer.readUInt8(currentOffset++);
      data.writeUInt8(mask ^ source, i);
    }
  } else {
    buffer.copy(data, 0, currentOffset++);
  }

  return data.toString("utf8");
};
