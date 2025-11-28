import cors from "cors";
import dotenv from "dotenv";
dotenv.config();
import express from "express";
import authRoutes from "./routes/authRoutes";
import jobRoutes from "./routes/jobRoutes";
import preferenceRoutes from "./routes/preferenceRoutes";
import cron from "node-cron";
import fetch from "node-fetch";
import alertRoutes from "./routes/alertRoutes";
import { sendAlertsToAllUsers } from "./controllers/notificationController";
import adminRoutes from "./routes/adminRoutes";

const app = express();

// ----------------------------------------------------
// CORS SETUP
// ----------------------------------------------------
const FRONTEND_URL = process.env.FRONTEND_URL || "";

// jo jo origins ko allow karna hai unki list
const allowedOrigins = [
  "http://localhost:5173",      // normal Vite dev
  "http://127.0.0.1:5173",      // kabhi kabhi ye use hota hai
  "http://172.17.160.1:8080",   // tumhare screenshot wala local preview
  FRONTEND_URL,                 // deployed frontend (Render etc)
].filter(Boolean);

console.log("Allowed CORS origins:", allowedOrigins);

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:8080",
      FRONTEND_URL
    ].filter(Boolean),
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.options("*", cors());


app.use(express.json());

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

// ----------------------------------------------------
// ROUTES
// ----------------------------------------------------
app.use("/api/auth", authRoutes);
app.use("/api/preferences", preferenceRoutes);
app.use("/api/jobs", jobRoutes);
app.use("/api/alerts", alertRoutes);
app.use("/api/admin", adminRoutes);

// Root route
app.get("/", (req, res) => {
  res.send("Backend Running ✅");
});

// ----------------------------------------------------
// SERVER START
// ----------------------------------------------------
const PORT = Number(process.env.PORT) || 4000;

app.listen(PORT, () => {
  console.log("Server running on port:", PORT);
});

// ----------------------------------------------------
// CRON JOB – auto fetch new jobs every 6 hours
// ----------------------------------------------------
const INTERNAL_BASE_URL =
  process.env.SERVER_URL || `http://localhost:${PORT}`;

cron.schedule("0 */6 * * *", async () => {
  try {
    console.log("🚀 Scheduled fetch: starting");
    await fetch(`${INTERNAL_BASE_URL}/api/jobs/fetch`, {
      method: "POST",
    });
    console.log("✅ Scheduled fetch: done");
  } catch (err) {
    console.error("Scheduled fetch failed:", err);
  }
});
