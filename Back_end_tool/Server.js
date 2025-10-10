const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const app = express();
const port = 5001;
const database = require("./src/config/database");
const clients = require("./src/utils/websocketStore"); // import store duy nhất
require("dotenv").config();
const cors = require("cors");

const whitelist = ["http://localhost:3000", "http://localhost:5173"];
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || whitelist.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Tạo HTTP server và gắn WebSocket
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// WebSocket connection
wss.on("connection", (ws, req) => {
  const urlParams = new URLSearchParams(req.url.split("?")[1]);
  const scanId = urlParams.get("scanId");

  if (!scanId) {
    ws.close(1008, "Missing scanId");
    return;
  }

  console.log("🔌 Client connected with scanId:", scanId);
  clients.set(scanId, ws);

  ws.send(JSON.stringify({ type: "status", message: "Connected to server." }));

  ws.on("close", () => {
    console.log("❌ Client disconnected:", scanId);
    clients.delete(scanId);
  });
});

// Routes
const routerClient = require("./src/router/users/index.notcheck.routes");
const routerClientCheck = require("./src/router/users/index.check.routes");
routerClient(app);
routerClientCheck(app);

// Kết nối database
database.connect();

// Khởi động server
server.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

// Xuất server để controller sử dụng nếu cần
module.exports = { server, wss };
