//////////////////////////////// START CRM calibruce ///////////////////////////////

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import axios from "axios";
import multer from 'multer';
import fs from "fs";
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import PQueue from "p-queue";
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.json()); // Parses JSON from client
app.use(express.urlencoded({ extended: true })); // Required for TwiML endpoint
// ✅ ES Modules style
const API_VERSION = 'v22.0';
import mime from 'mime-types';
import 'dotenv/config'; // Used instead of require("dotenv").config()
import sql from 'mssql'; // <--- Use 'import' instead of 'require'
import twilio from 'twilio';
// --- Express App Setup ---

// Multer setup to store file in memory (buffer)
const storage = multer.memoryStorage();
const OTP_STORE = {}; // Temporary store { phoneNumber: otp }
import FormData from 'form-data'; // Needed for multipart/form-data
// -------------------------------
// 1. APP INIT (MUST BE FIRST)
// -------------------------------
// WhatsApp API credentials from environment variables
const PHONE_NUMBER_ID = process.env.PHONE_NUMBER_ID;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
const PORT = process.env.BACKEND_PORT || 5000; // ✅ MATCH FRONTEND
const WEBHOOK_VERIFY_TOKEN = process.env.WEBHOOK_VERIFY_TOKEN

// ==================================================
// 1️⃣ REGISTER WEBHOOK VERIFY TOKEN (FROM FRONTEND)
// ==================================================
app.post('/api/register-webhook-token', (req, res) => {
  const { verifyToken } = req.body;

  if (!verifyToken) {
    return res.status(400).json({
      success: false,
      error: 'verifyToken is required'
    });
  }

  verifyTokenStore.add(verifyToken);
  console.log('Registered verify token:', verifyToken);

  res.json({ success: true });
});

// =======================================================
// WHATSAPP WEBHOOK Verification
// =======================================================

// ✅ Verification
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  console.log('Webhook verification attempt:', { mode, token, challenge });

  if (mode === 'subscribe' && token === WEBHOOK_VERIFY_TOKEN) {
    console.log('Webhook verified successfully!');
    return res.status(200).send(challenge);
  }

  console.log('Webhook verification failed!');
  return res.status(403).send('Verification failed');
});

// -------------------------------
// 2. GLOBAL MIDDLEWARE
// -------------------------------
// -------------------------------
// CORS + BODY PARSERS + LOGGER
// -------------------------------
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow server-side tools like Postman / curl
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// Body parsers
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Debug logger (POST requests only)
app.use((req, _res, next) => {
  if (req.method === "POST") {
    console.log("--------------------------------------------------");
    console.log(
      `[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`
    );
    console.log("Request Body:");
    console.log(JSON.stringify(req.body, null, 2));
    console.log("--------------------------------------------------");
  }
  next();
});

// -------------------------------
// ES MODULE __dirname SETUP
// -------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const allowedOrigins = ["http://localhost:3000","http://localhost:3001"];

/** * Utility: Detect WhatsApp media type from MIME 
 * This is needed for the final /messages API call.
 */
const getMediaType = (mime) => {
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("audio/")) return "audio";
  if (mime.startsWith("video/")) return "video";
  // The 'document' type covers PDF, text, and other files
  if (mime === "application/pdf" || mime === "text/plain" || mime.startsWith("application/msword")) return "document";
  return "document";
};

  

app.use(bodyParser.json({ limit: '1mb' }));

app.use(bodyParser.json());

const TOKEN_STORE = {};

const normalizePhoneNumber = (num) =>
  typeof num === 'string' ? num.replace(/\s/g, '').replace(/^\+/, '') : '';
app.use(bodyParser.urlencoded({ extended: true }));

/* ================= MULTER ================= */
const upload1 = multer({storage: multer.memoryStorage(),limits: { fileSize: 25 * 1024 * 1024 }});
// The endpoint the React frontend calls
app.post("/upload1", upload1.single("file"), async (req, res) => {
  // Get dynamic inputs
  const appId = req.headers["x-app-id"]; // From custom header
  const { accessToken } = req.body;      // From form-data body

  if (!appId || !accessToken || !req.file) {
    return res.status(400).json({ error: "App ID, Access Token, and file are required" });
  }

  // File metadata from Multer
  const { path, originalname, mimetype, size ,buffer } = req.file;
  const mediaType = getMediaType(mimetype);
  
  try {
    // --- STEP 1: Create upload session ---
    const sessionRes = await axios.post(
      `https://graph.facebook.com/v24.0/${appId}/uploads`,
      null, // No body required for the session creation POST
      {
        params: {
          file_name: originalname,
          file_length: size,         // CRITICAL: Must be exact file size
          file_type: mimetype,       // CRITICAL: Must be exact MIME type
        },
        // IMPORTANT: Access token passed as a Bearer token in the Authorization header
        headers: {
            Authorization: `Bearer ${accessToken}`,
        }
      }
    );

    const uploadId = sessionRes.data.id; // e.g., "upload:1171617668480245"
    console.log("STEP 1 Success: Upload Session ID created:", uploadId);
    
    const uploadRes = await axios.post(
      `https://graph.facebook.com/v24.0/${uploadId}`, // Use the session ID
      buffer, // Pass the raw binary buffer as the body
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": mimetype, // CRITICAL: Must match the file's MIME type
          "file_offset": "0", // Start of the file
        },
        // Prevents Axios from prematurely closing the connection for large files
        maxBodyLength: Infinity, 
        maxContentLength: Infinity,
      }
    );

    console.log("STEP 2 Success: File uploaded. Media Handle (h) received.");

    // Return the media handle (h) and file details to the React frontend
    return res.json({
      h: uploadRes.data.h, // The final media ID needed for the /messages API
      mediaType,
      originalname,
      mimetype,
      size,
    });

  } catch (error) {
    // Log the detailed error from Meta/Axios
    console.error("META API Error:", error.response?.data || error.message);
    // Return the error to the React frontend
    return res.status(500).json({
      error: error.response?.data || error.message
    });
  }
});


app.post('/api/upload-media', upload1.single('file'), async (req, res) => {
  console.log('--- Multer Debug ---');
  console.log('req.body:', req.body); // Should contain accessToken, phoneNumberId
  console.log('req.file:', req.file); // Should contain the file buffer/metadata
  try {
    const { phoneNumberId, accessToken } = req.body;
    const file = req.file;

    if (!file) return res.status(400).json({ error: 'No file uploaded.' });
    if (!phoneNumberId || !accessToken) return res.status(400).json({ error: 'Missing configuration fields.' });

    const formData = new FormData();
    formData.append('file', file.buffer, { filename: file.originalname, contentType: file.mimetype });
    formData.append('messaging_product', 'whatsapp');

    const response = await axios.post(
      `https://graph.facebook.com/v22.0/${phoneNumberId}/media`,
      formData,
      { headers: { Authorization: `Bearer ${accessToken}`, ...formData.getHeaders() } }
    );

    res.json({ mediaId: response.data.id });

  } catch (err) {
    console.error('Media Upload Error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Media upload failed', details: err.response?.data || err.message });
  }
});


///////////////////////// 01.Fetch Templates List  from Meta//////////////////////
// 👉 API to fetch WhatsApp templates
app.post("/api/templates", async (req, res) => {
  const { wabaId, accessToken } = req.body;

  if (!wabaId || !accessToken) {
    return res.status(400).json({ error: "WABA ID and Access Token required" });
  }

  try {
    const response = await axios.get(
      `https://graph.facebook.com/v23.0/${wabaId}/message_templates`,
      {
        params: { fields: "name,status" },
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );
    const templates = response.data.data.map(t => ({
      name: t.name,
      status: t.status,
    }));

    res.json({ templates });
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: "Failed to fetch templates" });
  }
});

///////////////////////// 02. watsup text message sender ////////////////////
/* ---------------- SEND TEXT MESSAGE ---------------- */

app.post("/api/send-text", async (req, res) => {
  const {
    phoneNumberId,
    accessToken,
    phoneNumber,
    messageBody,
    previewUrl,
  } = req.body;

  // ✅ Validation
  if (!phoneNumberId || !accessToken || !phoneNumber || !messageBody) {
    return res.status(400).json({
      success: false,
      error: "Missing required fields",
    });
  }

  try {
    const url = `https://graph.facebook.com/v18.0/${phoneNumberId}/messages`;

    const payload = {
      messaging_product: "whatsapp",
      to: phoneNumber,
      type: "text",
      text: {
        body: messageBody,
        preview_url: previewUrl || false,
      },
    };

    const response = await axios.post(url, payload, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    });

    return res.json({
      success: true,
      messageId: response.data.messages?.[0]?.id,
    });
  } catch (error) {
    console.error("WhatsApp API Error:", error.response?.data || error.message);

    return res.status(500).json({
      success: false,
      error:
        error.response?.data?.error?.message ||
        "Failed to send WhatsApp message",
    });
  }
});


//---------------- 03. Send WhatsApp Location ----------------
app.post("/api/send-location", async (req, res) => {
  try {
    const {
      phoneNumber,
      locationData,
      accessToken,
      phoneNumberId,
    } = req.body;

    // ---------- Validation ----------
    if (!phoneNumber) {
      return res.status(400).json({
        success: false,
        message: "phoneNumber is required",
      });
    }

    if (!accessToken) {
      return res.status(400).json({
        success: false,
        message: "accessToken is required",
      });
    }

    if (!phoneNumberId) {
      return res.status(400).json({
        success: false,
        message: "phoneNumberId is required",
      });
    }

    if (!locationData) {
      return res.status(400).json({
        success: false,
        message: "locationData is required",
      });
    }

    const { latitude, longitude, name, address } = locationData;

    if (!latitude || !longitude) {
      return res.status(400).json({
        success: false,
        message: "latitude and longitude are required",
      });
    }

    // ---------- WhatsApp Location Payload ----------
    const payload = {
      messaging_product: "whatsapp",
      to: phoneNumber,
      type: "location",
      location: {
        latitude: Number(latitude),
        longitude: Number(longitude),
        name: name || "Shared Location",
        address: address || "",
      },
    };

    // ---------- Send to WhatsApp ----------
    const response = await axios.post(
      `https://graph.facebook.com/v22.0/${phoneNumberId}/messages`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );

    // ---------- Success ----------
    return res.json({
      success: true,
      message: `✅ Location sent to ${phoneNumber}`,
      whatsappMessageId: response.data?.messages?.[0]?.id || null,
    });
  } catch (error) {
    console.error("❌ WhatsApp API Error:", error.response?.data || error.message);

    return res.status(500).json({
      success: false,
      message:
        error.response?.data?.error?.message ||
        "Failed to send WhatsApp location",
    });
  }
});

/////////////////////////////// 04.Media id creation and sending Template messages///////

app.post("/api/create-template01", async (req, res) => {
  try {
    const {
      template_name,
      header_format,    // "image", "document", "audio", "video"
      h,                // MEDIA HANDLE from upload API
      placeholders,     // ["Fouzia", "INV-123"]
      wabaId,
      accessToken
    } = req.body;

    /* ================= VALIDATION ================= */
    if (!template_name)
      return res.status(400).json({ error: "template_name missing" });

    if (!header_format)
      return res.status(400).json({ error: "header_format missing" });

    if (!h)
      return res.status(400).json({ error: "media handle (h) missing" });

    if (!wabaId)
      return res.status(400).json({ error: "wabaId missing" });

    if (!accessToken)
      return res.status(400).json({ error: "accessToken missing" });

    if (!Array.isArray(placeholders) || placeholders.length === 0)
      return res.status(400).json({ error: "placeholders missing or invalid" });

    /* ================= TEMPLATE TEXT ================= */
    const bodyText =
      "Hello {{1}}, your invoice number is {{2}}. Please check the attached PDF.";

    const footerText = "Hello its from Calibruce";

    /* ================= COMPONENTS ================= */
    const components = [
      {
        type: "HEADER",
        format: header_format.toUpperCase(), // IMAGE | DOCUMENT
        example: {
          header_handle: [h]
        }
      },
      {
        type: "BODY",
        text: bodyText,
        example: {
          body_text: [placeholders] // Meta requires array of arrays
        }
      },
      {
        type: "FOOTER",
        text: footerText
      }
    ];

    const payload = {
      name: template_name,
      language: "en_US",
      category: "UTILITY",
      components
    };

    /* ================= META API CALL ================= */
    const response = await axios.post(
      `https://graph.facebook.com/v20.0/${wabaId}/message_templates`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        }
      }
    );

    return res.json({
      success: true,
      template: response.data
    });

  } catch (err) {
    console.error("Template creation error:", err.response?.data || err.message);
    return res.status(500).json({
      error: err.response?.data || "Failed to create template"
    });
  }
});

app.post("/api/send-template01", async (req, res) => {
  try {
    const {
      phoneNumbers,
      templateName,
      templateType, // "image" or "document"
      phoneNumberId,
      accessToken,
      placeholders = [], // array of placeholder values
    } = req.body;

    if (!Array.isArray(placeholders) || placeholders.length === 0) {
      return res.status(400).json({ error: "Placeholders are required" });
    }

    for (const to of phoneNumbers) {
      const templatePayload = {
        name: templateName,
        language: { code: "en_US" },
        components: [
          {
            type: "body",
            parameters: placeholders.map((p) => ({ type: "text", text: p })),
          },
        ],
      };

      // For document or image templates, WhatsApp API requires same body placeholders
      const payload = {
        messaging_product: "whatsapp",
        to,
        type: "template",
        template: templatePayload,
      };

      await axios.post(
        `https://graph.facebook.com/v20.0/${phoneNumberId}/messages`,
        payload,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
          },
        }
      );
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err.response?.data || err);
    res.status(500).json({ error: "Failed to send messages" });
  }
});

////////////////////////////////////05.orderconformation Template///////////////////
                  //Create WhatsApp Template
app.post("/api/create-template03", async (req, res) => {
  try {
    const {
      templateName,
      wabaId,
      accessToken,
      documentHandle,
      bodyPlaceholders,
      buttons = []
    } = req.body;

    /* ================= VALIDATION ================= */
    if (!templateName || !wabaId || !accessToken || !documentHandle) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (!Array.isArray(bodyPlaceholders) || bodyPlaceholders.length < 1) {
      return res.status(400).json({ error: "Invalid body placeholders" });
    }

    /* ================= VALIDATE BUTTONS ================= */
    const validatedButtons = buttons.map((b) => {
      if (!b.type || !b.text) {
        throw new Error("Button type and text are required");
      }

      if (b.type === "PHONE_NUMBER") {
        if (!/^\+\d{10,15}$/.test(b.phone_number)) {
          throw new Error(`Invalid phone number: ${b.phone_number}`);
        }
        return {
          type: "PHONE_NUMBER",
          text: b.text,
          phone_number: b.phone_number
        };
      }

      if (b.type === "URL") {
        if (!/^https?:\/\/.+/.test(b.url)) {
          throw new Error(`Invalid URL: ${b.url}`);
        }
        return {
          type: "URL",
          text: b.text,
          url: b.url
        };
      }

      throw new Error(`Unsupported button type: ${b.type}`);
    });

    /* ================= TEMPLATE PAYLOAD ================= */
    const payload = {
      name: templateName,
      language: "en_US",
      category: "UTILITY",
      components: [
        {
          type: "HEADER",
          format: "DOCUMENT",
          example: {
            header_handle: [documentHandle]
          }
        },
        {
          type: "BODY",
          text:
            "Thank you for your order, {{1}}! Your order number is {{2}}. Tap the PDF linked above to view your receipt.",
          example: {
            body_text: [bodyPlaceholders]
          }
        }
      ]
    };

    if (validatedButtons.length > 0) {
      payload.components.push({
        type: "BUTTONS",
        buttons: validatedButtons
      });
    }

    /* ================= SEND TO META ================= */
    const response = await axios.post(
      `https://graph.facebook.com/v22.0/${wabaId}/message_templates`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        }
      }
    );

    res.json({
      success: true,
      message: "Template created successfully (Pending approval)",
      data: response.data
    });
  } catch (error) {
    console.error("Template creation failed:", error.response?.data || error.message);
    res.status(500).json({
      error: error.response?.data || error.message
    });
  }
});
                // Send Approved Template
app.post("/api/send-template03", async (req, res) => {
  try {
    const {
      phoneNumbers,
      templateName,
      phoneNumberId,
      accessToken,
      placeholders,
      documentHandle,
      mediaType
    } = req.body;

    // ---------- VALIDATION ----------
    if (!Array.isArray(phoneNumbers) || phoneNumbers.length === 0) {
      return res.status(400).json({ error: "Phone numbers are required" });
    }

    if (!templateName?.trim()) {
      return res.status(400).json({ error: "Template name is required" });
    }

    if (!phoneNumberId?.trim()) {
      return res.status(400).json({ error: "Phone Number ID is required" });
    }

    if (!accessToken?.trim()) {
      return res.status(400).json({ error: "Access Token is required" });
    }

    if (documentHandle ?.trim()) {
      return res.status(400).json({ error: "Invalid media handle" });
    }

    // ---------- PREPARE TEMPLATE COMPONENTS ----------
    const buildComponents = () => {
      const components = [];

      // BODY placeholders
      if (placeholders.length > 0) {
        components.push({
          type: "body",
          parameters: placeholders.map(text => ({
            type: "text",
            text
          }))
        });
      }

      // HEADER media (optional)
      if (documentHandle && mediaType) {
        const mediaCategory = mediaType.startsWith("image")
          ? "image"
          : mediaType.startsWith("video")
          ? "video"
          : "document";

        components.push({
          type: "header",
          parameters: [
            {
              type: mediaCategory,
              [mediaCategory]: { id: documentHandle }
            }
          ]
        });
      }

      return components;
    };

    // ---------- SEND LOOP ----------
    const results = [];
    let sentCount = 0;

    for (const number of phoneNumbers) {
      try {
        const response = await axios.post(
          `https://graph.facebook.com/v16.0/${phoneNumberId}/messages`,
          {
            messaging_product: "whatsapp",
            to: number,
            type: "template",
            template: {
              name: templateName,
              language: { code: "en_US" },
              components: buildComponents()
            }
          },
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
              "Content-Type": "application/json"
            }
          }
        );

        sentCount++;
        results.push({
          number,
          status: "sent",
          messageId: response.data.messages?.[0]?.id
        });

      } catch (err) {
        console.error(`❌ Failed for ${number}:`, err.response?.data || err.message);

        results.push({
          number,
          status: "failed",
          error: err.response?.data || err.message
        });
      }
    }

    // ---------- FINAL RESPONSE ----------
    res.json({
      success: true,
      sent_count: sentCount,
      total: phoneNumbers.length,
      results
    });

  } catch (err) {
    console.error("🔥 /api/send-template03 error:", err);
    res.status(500).json({ error: err.message });
  }
});

///////////////////06 & 07 watsup Wedding invitation and autoreply////////////////////////
// = WHATSAPP   marriage invitation MESSAGES // =======================================================
// --------------------
// In-memory stores
// --------------------
const verifyTokenStore = new Set();            // webhook verify tokens
const credentialStore = new Map();             // phoneNumberId -> accessToken

// --------------------
// Utils
// --------------------
app.use(bodyParser.urlencoded({ extended: true }));

let allowedReplyNumbers = new Set();
let rsvpResponses = {};

//// =======================
// Create Dynamic Marriage Template
// =======================
app.post("/api/create-template", async (req, res) => {
  try {
    const {
      template_name,
      header_media_id, // renamed for clarity
      wabaId,
      accessToken,
      placeholders
    } = req.body;

    if (
      !template_name ||
      !header_media_id ||
      !wabaId ||
      !accessToken ||
      !Array.isArray(placeholders)
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const bodyText = `🌸 You're Invited! 🌸

Join us in celebrating the sacred union of
👰 {{1}} & 🤵 {{2}}

📅 Date: {{3}}
📍 Venue: {{4}}

Your presence will make our day complete! 💍✨`;

    const payload = {
      name: template_name,
      language: "en_US",
      category: "MARKETING", // ✅ safer for invitations
      components: [
        {
          type: "HEADER",
          format: "IMAGE",
          example: {
            header_handle: [header_media_id]
          }
        },
        {
          type: "BODY",
          text: bodyText,
          example: {
            body_text: [placeholders]
          }
        },
       {
      type: "BUTTONS",
      buttons: [
        { type: "QUICK_REPLY", text: "Yes, I'll attend" },
        { type: "QUICK_REPLY", text: "No, can't make it" },
        { type: "QUICK_REPLY", text: "Will confirm later" }
      ]
    }
      ]
    };



    const response = await axios.post(
      `https://graph.facebook.com/v20.0/${wabaId}/message_templates`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        }
      }
    );

    res.json(response.data);
  } catch (err) {
    console.error("Template creation failed:", err.response?.data || err);
    res.status(500).json({
      error: err.response?.data || "Failed to create template"
    });
  }
});
/* ---------------------------------------------------
   2️⃣ Send WhatsApp Template marriage
--------------------------------------------------- */
app.post("/api/send-invitation", async (req, res) => {
  try {
    const {
      phoneNumbers,
      templateName,
      placeholder_values, // [[p1, p2, p3, p4]]
      phoneNumberId,
      accessToken,
      mediaHandle
    } = req.body;

    /* ================= VALIDATION ================= */
    if (
      !Array.isArray(phoneNumbers) ||
      phoneNumbers.length === 0 ||
      !templateName ||
      !phoneNumberId ||
      !accessToken ||
      !mediaHandle ||
      !Array.isArray(placeholder_values) ||
      !Array.isArray(placeholder_values[0]) ||
      placeholder_values[0].length !== 4
    ) {
      return res.status(400).json({
        error: "Invalid payload. Exactly 4 placeholders are required."
      });
    }

    /* ================= CLEAN PLACEHOLDERS ================= */
    const placeholders = placeholder_values[0].map(v =>
      String(v).trim().replace(/^"+|"+$/g, "")
    );

    if (placeholders.some(v => v === "")) {
      return res.status(400).json({
        error: "All placeholder values must be non-empty"
      });
    }

    /* ================= CLEAN PHONE NUMBERS ================= */
    const cleanNumbers = [...new Set(phoneNumbers)]
      .map(n => String(n).replace(/\D/g, ""))
      .filter(n => /^\d{10,15}$/.test(n));

    if (!cleanNumbers.length) {
      return res.status(400).json({ error: "No valid phone numbers found" });
    }

    const results = [];

    /* ================= SEND LOOP ================= */
     /* ================= SEND LOOP ================= */
for (const to of cleanNumbers) {
  const payload = {
    messaging_product: "whatsapp",
    to,
    type: "template",
    template: {
      name: templateName.toLowerCase(),
      language: { code: "en_US" },
      components: [
        {
          type: "header",
          parameters: [
            {
              type: "image",
              image: { id: mediaHandle }
            }
          ]
        },
        {
          type: "body",
          parameters: placeholders.map(text => ({
            type: "text",
            text
          }))
        },
      ]
    }
  };

      try {
        await axios.post(
          `https://graph.facebook.com/v22.0/${phoneNumberId}/messages`,
          payload,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
              "Content-Type": "application/json"
            }
          }
        );

        results.push({ number: to, success: true });
      } catch (err) {
        results.push({
          number: to,
          success: false,
          error: err.response?.data || err.message
        });
      }
    }

    res.json({ success: true, results });

  } catch (err) {
    console.error("Send Invitation Error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});
/* =====================================================
   API: CREATE TEXT TEMPLATE for Autoreply
===================================================== */
app.post('/api/create-text-template', async (req, res) => {
  try {
    const { template_name, category, bodyText, wabaId, accessToken } = req.body;

    if (!template_name || !category || !bodyText || !wabaId || !accessToken) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const payload = {
      name: template_name.toLowerCase(),   // ✅ REQUIRED
      language: 'en_US',                   // ✅ CORRECT FORMAT
      category,                            // UTILITY / MARKETING / AUTHENTICATION
      components: [
        {
          type: 'BODY',
          text: bodyText                   // ✅ STATIC AUTO-REPLY TEXT
        }
      ]
    };
    const response = await axios.post(
      `https://graph.facebook.com/v22.0/${wabaId}/message_templates`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    res.json({
      success: true,
      status: response.data.status || 'PENDING',
      data: response.data
    });

  } catch (err) {
    console.error('❌ Template creation error:', err.response?.data || err.message);
    res.status(500).json({
      error: err.response?.data || err.message
    });
  }
});
/* =====================================================
   API: SEND TEMPLATE MESSAGES for Autoreply
===================================================== */

app.post("/api/send-template-messages", async (req, res) => {
  try {
    const { templateName, phoneNumbers, accessToken, phoneNumberId } = req.body;

    if (
      !templateName ||
      !Array.isArray(phoneNumbers) ||
      phoneNumbers.length === 0 ||
      !accessToken ||
      !phoneNumberId
    ) {
      return res.status(400).json({ error: "Missing required data" });
    }

    const results = [];

    for (const num of phoneNumbers) {
      const normalized = num.replace(/\D/g, "");

      if (normalized.length < 10) {
        results.push({
          to: num,
          success: false,
          error: "Invalid phone number"
        });
        continue;
      }

      // ✅ STORE TEMPLATE FOR WEBHOOK USE
      phoneTemplateMap.set(normalized, templateName);

      try {
        const payload = {
          messaging_product: "whatsapp",
          to: normalized,
          type: "template",
          template: {
            name: templateName,
            language: { code: "en_US" }
          }
        };

        await axios.post(
          `https://graph.facebook.com/v18.0/${phoneNumberId}/messages`,
          payload,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
              "Content-Type": "application/json"
            }
          }
        );

        results.push({ to: normalized, success: true });
      } catch (err) {
        results.push({
          to: normalized,
          success: false,
          error: err.response?.data || err.message
        });
      }
    }

    console.log("📌 Stored template mappings:", [...phoneTemplateMap.entries()]);

    res.json({ success: true, results });
  } catch (err) {
    console.error("❌ Send template error:", err);
    res.status(500).json({ error: err.message });
  }
});


// Webhook Event Handler (POST request) Meta sends POST requests to this endpoint for incoming messages and other events.//
const processedMessageIds = new Set();
const phoneTemplateMap = new Map(); // 🔑 set in /api/send-template-mes

/* =====================================================
   WEBHOOK RECEIVER for interactive messaging for both marriage and autoreply messaging 
===================================================== */
const queue = new PQueue({
  concurrency: 1,   // process one message at a time
  intervalCap: 10,  // optional rate limit
  interval: 1000
});
app.post("/webhook", (req, res) => {
  // Respond immediately (Meta requirement)
  res.status(200).json({ status: "EVENT_RECEIVED" });

  processWebhook(req.body).catch(err =>
    console.error("❌ Webhook async error:", err.message)
  );
});

/* =====================================================
   WEBHOOK PROCESSOR
===================================================== */
async function processWebhook(body) {
  if (body.object !== "whatsapp_business_account") return;

  const messages = [];

  for (const entry of body.entry || []) {
    for (const change of entry.changes || []) {
      if (change.field !== "messages") continue;
      messages.push(...(change.value?.messages || []));
    }
  }

  // De-duplicate messages
  const newMessages = messages.filter(msg => !processedMessageIds.has(msg.id));
  newMessages.forEach(msg => processedMessageIds.add(msg.id));

  // Queue processing
  for (const msg of newMessages) {
    queue.add(() => handleIncomingMessage(msg));
  }
}

/* =====================================================
   MESSAGE HANDLER
===================================================== */
async function handleIncomingMessage(message) {
  const rawFrom = message.from;
  const from = normalizePhoneNumber(rawFrom);

  if (allowedReplyNumbers.size && !allowedReplyNumbers.has(from)) {
    console.log("🚫 Not allowed to reply:", from);
    return;
  }

  let replyText = null;
  let templateName = null;
  let components = [];

  /* ---------- INTERACTIVE (BUTTON REPLIES) ---------- */
  if (message.type === "interactive") {
    const buttonId = message.interactive?.button_reply?.id;

    switch (buttonId) {
      case "Yes":
        rsvpResponses[from] = "yes";
        replyText = "Wonderful! Thank you for confirming your attendance 🎉";
        break;

      case "No":
        rsvpResponses[from] = "no";
        replyText = "Thanks for letting us know. We’ll miss you!";
        break;

      case "Will Confirm Later":
        rsvpResponses[from] = "maybe";
        replyText = "No problem 😊 Please confirm whenever you’re ready.";
        break;

      default:
        replyText = "Thank you for your response!";
    }
  }

  /* ---------- TEXT MESSAGE → DYNAMIC TEMPLATE ---------- */
  else if (message.type === "text") {
    const storedTemplate = phoneTemplateMap.get(from);

    if (!storedTemplate) {
      console.log("⚠️ No template mapped for", from);
      return;
    }

    templateName = storedTemplate;
    components = [
      {
        type: "body",
        parameters: [
          { type: "text", text: message.text?.body || "" }
        ]
      }
    ];
  }

  /* ---------- SEND RESPONSE ---------- */
  if (templateName) {
    await sendWhatsAppTemplate(from, templateName, "en", components);
  } else if (replyText) {
    await sendWhatsAppText(rawFrom, replyText);
  }
}

/* =====================================================
   SEND TEMPLATE MESSAGE
===================================================== */
async function sendWhatsAppTemplate(
  to,
  templateName,
  language = "en",
  components = []
) {
  try {
    await axios.post(
      `https://graph.facebook.com/v22.0/${process.env.PHONE_NUMBER_ID}/messages`,
      {
        messaging_product: "whatsapp",
        to,
        type: "template",
        template: {
          name: templateName,
          language: { code: language },
          components
        }
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.ACCESS_TOKEN}`,
          "Content-Type": "application/json"
        }
      }
    );

    console.log("✅ Template auto-reply sent:", to, templateName);
  } catch (err) {
    console.error("❌ Template send failed:", err.response?.data || err.message);
  }
}
/* =====================================================
   SEND TEXT MESSAGE
===================================================== */
async function sendWhatsAppText(to, body) {
  try {
    await axios.post(
      `https://graph.facebook.com/v22.0/${process.env.PHONE_NUMBER_ID}/messages`,
      {
        messaging_product: "whatsapp",
        to,
        type: "text",
        text: { body }
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.ACCESS_TOKEN}`,
          "Content-Type": "application/json"
        }
      }
    );

    console.log("✅ Auto-reply text sent to", to);
  } catch (err) {
    console.error("❌ Text send failed:", err.response?.data || err.message);
  }
}
// =======================
// Get RSVP Status
// =======================
// RSVP Status Endpoint
app.get("/api/rsvp-status", (req, res) => {
  console.log("[API] RSVP status requested");

  let yesCount = 0;
  let noCount = 0;
  let maybeCount = 0;

  const respondedNumbers = new Set(Object.keys(rsvpResponses));

  console.log("[RSVP Debug] Raw responses:", rsvpResponses);

  Object.entries(rsvpResponses).forEach(([number, payload]) => {
    if (!payload) return;

    const normalizedPayload = payload.toString().trim().toLowerCase();

    console.log(
      `[RSVP Debug] Number: ${number}, Payload: ${normalizedPayload}`
    );

    switch (normalizedPayload) {
      case "yes":
        yesCount++;
        break;

      case "no":
        noCount++;
        break;

      case "will-confirm-later":
      case "maybe":
        maybeCount++;
        break;

      default:
        console.warn(
          `[RSVP Warning] Unknown RSVP value from ${number}: "${payload}"`
        );
        break;
    }
  });

  /* Count no-response numbers */
  let noResponseCount = 0;

  allowedReplyNumbers.forEach((number) => {
    if (!respondedNumbers.has(number)) {
      noResponseCount++;
    }
  });

  return res.status(200).json({
    success: true,
    rsvpResponses, // full data for debugging / UI drill-down
    summary: {
      totalInvited: allowedReplyNumbers.size,
      yes: yesCount,
      no: noCount,
      maybe: maybeCount,
      noResponse: noResponseCount,
    },
  });
});
///////////////////// 08. Watsup OTP Generation and Verification //////////////////////////////////////
function generateOTP(phoneNumber) {
  const secret = 'MY_SECRET_KEY';
  const timestamp = Math.floor(Date.now() / 1000 / 60); // changes every minute
  const hash = crypto.createHmac('sha256', secret).update(phoneNumber + timestamp).digest('hex');
  const otp = parseInt(hash.substring(0, 6), 16) % 1000000;
  return otp.toString().padStart(6, '0');
}

// Sanitize template name (Meta requirement)
function sanitizeTemplateName(name) {
  return name.toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 30);
}

// Step 1: Create template
app.post("/create-template02", async (req, res) => {
  const { wabaId, accessToken, templateName } = req.body;

  if (!wabaId || !accessToken || !templateName) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const payload = {
    name: templateName.toLowerCase().replace(/\s+/g, "_"),
    language: "en_US",
    category: "AUTHENTICATION",
    components: [
      {
      type: "BODY",
      add_security_recommendation: true
    },
      {
        type: "BUTTONS",
        buttons: [
        {
          type: "OTP",
           otp_type: "COPY_CODE"
        }
      ]
      }
    ]
  };

  try {
    const response = await axios.post(
      `https://graph.facebook.com/v17.0/${wabaId}/message_templates`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        }
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: error.response?.data || error.message });
  }
});


// Step 2: Send OTP
app.post('/send-otp', async (req, res) => {
  try {
    const { phoneNumber, wabaId, accessToken, templateName } = req.body;
    if (!phoneNumber || !wabaId || !accessToken || !templateName)
      return res.status(400).json({ error: 'All fields are required' });

    const otp = generateOTP(phoneNumber);

    await axios.post(
      `https://graph.facebook.com/v22.0/${wabaId}/messages`,
      {
        messaging_product: 'whatsapp',
        to: phoneNumber,
        type: 'template',
        template: {
          name: templateName,
          language: { code: 'en' },
          components: [{ type: 'body', parameters: [{ type: 'text', text: otp }] }],
        },
      },
      { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } }
    );

    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (err) {
    console.error(err.response?.data || err);
    res.status(500).json({ error: err.response?.data || 'Failed to send OTP' });
  }
});

// Step 3: Verify OTP
app.post('/verify-otp', (req, res) => {
  const { phoneNumber, userOtp } = req.body;
  if (!phoneNumber || !userOtp) return res.status(400).json({ error: 'Phone and OTP required' });

  const expectedOtp = generateOTP(phoneNumber);
  if (userOtp === expectedOtp) {
    return res.json({ success: true, message: 'OTP verified ✅' });
  } else {
    return res.status(400).json({ success: false, message: 'Invalid OTP ❌' });
  }
});



///////////////////////// 09.EXOTAL Phone Call///////////////////////////
// EXOTEL CALL
 // 1️⃣ MAKE CALL (SECURE PROXY to Exotel)
// ------------------------------
 // ------------------------------
//  Trigger Exotel Call
// ------------------------------
app.post("/api/make-call", async (req, res) => {
  const { username, password, fromNumber, toNumber, callerId } = req.body;

  if (!username || !password || !fromNumber || !toNumber || !callerId) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const formData = new URLSearchParams();
    formData.append("From", fromNumber);
    formData.append("To", toNumber);
    formData.append("callerId", callerId);
    formData.append("record", "true");

    const response = await axios.post(
      "https://api.exotel.com/v1/Accounts/calibrecueitsolutions1/Calls/connect",
      formData,
      {
        auth: { username, password },
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error("Backend error:", error.response?.data || error.message);
    res
      .status(error.response?.status || 500)
      .json(error.response?.data || { error: error.message });
  }
});

// ------------------------------
// 2️⃣ GET CALL HISTORY
// ------------------------------
app.get("/api/call-history", async (req, res) => {
  const { username, password, accountSid, subDomain, startDate, endDate } = req.query;

  if (!username || !password || !accountSid || !subDomain) {
    return res.status(400).json({ error: "Missing credentials" });
  }

  try {
    let url = `https://${subDomain}/v1/Accounts/${accountSid}/Calls.json`;

    if (startDate && endDate) {
      const s = startDate.replace(" ", "T");
      const e = endDate.replace(" ", "T");
      url += `?StartTime=${encodeURIComponent(s)}&EndTime=${encodeURIComponent(e)}`;
    }

    const response = await axios.get(url, {
      auth: { username, password },
    });

    res.json(response.data);
  } catch (err) {
    console.error("Exotel error:", err.response?.data || err.message);
    res.status(err.response?.status || 500).json(err.response?.data || { error: "Exotel API error" });
  }
});

// ------------------------------
// 3️⃣ GET CALL DETAILS
// ------------------------------
app.get("/api/call-details/:sid", async (req, res) => {
    const { username, password, accountSid, subDomain } = req.query;
    const callSid = req.params.sid;

    if (!username || !password || !accountSid || !subDomain) {
        return res.status(400).json({ error: "Missing credentials, AccountSid or SubDomain" });
    }

    try {
        const url = `https://${subDomain}/v1/Accounts/${accountSid}/Calls/${callSid}.json`;
        const response = await axios.get(url, {
            auth: { username, password },
        });

        res.json(response.data);
    } catch (err) {
        console.error(err.response?.data || err.message);
        res.status(500).json({ error: "Exotel API error" });
    }
});

// ------------------------------
// 4️⃣ CONNECT.XML (TwiML)
// ------------------------------
//4️⃣// CONNECT.XML (TwiML Endpoint - Called by Exotel)
// ------------------------------
app.post("/connect.xml", (req, res) => {
    // Exotel sends 'To' (customer number) in the URL-encoded body
    const { To } = req.body; 

    const xmlResponse = `
        <Response>
            <Say voice="alice">Connecting your call now.</Say>
            <Dial>${To}</Dial>
        </Response>
    `.trim();

    res.header("Content-Type", "application/xml");
    res.send(xmlResponse);
});
///////////////////10. Twilio Messaging services //////////////////////

/* ================= DATABASE CONFIGURATION ================= */

const dbConfig = {
  server: "DESKTOP-BUGKGO7",
  database: "TwilioDB",
  user: "nodeuser",
  password: "Node@123",
  options: {
    encrypt: false,
    trustServerCertificate: true
  }
};

// Global Connection Pool Promise
const poolPromise = new sql.ConnectionPool(dbConfig)
  .connect()
  .then(pool => {
    console.log("✅ DB Connected");
    return pool;
  })
  .catch(err => {
    console.error("❌ DB Error", err.message);
    // If the DB connection fails, exit the process immediately
    process.exit(1);
  });


/* ================= API Endpoints (STRICTLY CUSTOM LOGIC) ================= */

// Helper function to get pool instance and handle connection errors
async function getDbPool(res) {
    let pool;
    try {
        pool = await poolPromise;
        return pool;
    } catch (e) {
        console.error('Database pool is unavailable:', e);
        res.status(503).json({ success: false, message: 'Database service unavailable.' });
        return null;
    }
}

// --- STEP 1: LOGIN VERIFY (Sets Users.is_verified = 1) ---
// Condition: is_verified must be TRUE when login credentials match. (Step 1 -> Step 2)
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Username and password required" });
  }
    const pool = await getDbPool(res);
    if (!pool) return;

  try {
    // 1. Verify Username and Password
    const result = await pool.request()
      .input("username", sql.VarChar, username)
      .input("password", sql.VarChar, password)
      .query(`
        SELECT id
        FROM dbo.Users 
        WHERE username=@username AND password=@password
      `);

    if (!result.recordset.length) {
      return res.status(401).json({ success: false, message: "Invalid username or password" });
    }

    const userId = result.recordset[0].id;

    // 2. CRITICAL: Set Users.is_verified = 1 immediately after credentials match
    await pool.request()
        .input("userId", sql.Int, userId)
        .query(`UPDATE dbo.Users SET is_verified = 1 WHERE id = @userId`);
    
    // 3. Login is successful (Frontend moves to Step 2)
    res.json({ success: true, userId: userId });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// --- STEP 2: TWILIO CREDENTIAL VERIFICATION ---
app.post("/api/verify-twilio", async (req, res) => {
  const { sid, token } = req.body;
  
  if (!sid || !token) {
    return res.status(400).json({ success: false, message: "SID and Token required" });
  }
  
  try {
    const client = twilio(sid, token);
    await client.api.accounts(sid).fetch(); 
    res.json({ success: true, message: "Twilio credentials are valid" });
  } catch (err) {
    console.error("Twilio verification failed:", err.message);
    res.status(401).json({ success: false, message: "Invalid Twilio credentials" });
  }
});

// --- STEP 3: SEND OTP (Initializes OTP record with is_verified = 0) ---
app.post("/api/send-otp", async (req, res) => {
  const { userId, phone, twilioData } = req.body;
  
  if (!userId || !phone || !twilioData || !twilioData.sid || !twilioData.from) {
    return res.status(400).json({ success: false, message: "Missing required data" });
  }

    const pool = await getDbPool(res);
    if (!pool) return;

  try {
    const otp = Math.floor(100000 + Math.random() * 900000);

    // 1. Store OTP in dbo.OTPs with is_verified = 0 (unused)
    await pool.request()
      .input("userId", sql.Int, userId)
      .input("otp", sql.Int, otp)
      .query(`
        INSERT INTO dbo.OTPs (user_id, otp_code, is_verified, created_at)
        VALUES (@userId, @otp, 0, GETDATE())
      `);

    // 2. Send SMS via Twilio
    const { sid, token, from } = twilioData;
    const client = twilio(sid, token);
    const body = `Your verification code is: ${otp}.`;
    
    await client.messages.create({ 
      from, 
      to: phone, 
      body 
    });

    res.json({ success: true, message: "OTP generated and sent successfully" });

  } catch (err) {
    console.error("Send OTP error:", err);
    res.status(500).json({ success: false, message: "Failed to send SMS." });
  }
});

// --- STEP 4: OTP VERIFY (Updates OTPs.is_verified = 1, DOES NOT affect Users.is_verified) ---
app.post("/api/verify-otp", async (req, res) => {
  const { userId, otp } = req.body;
  
    if (!userId || !otp) {
        return res.status(400).json({ success: false, message: "User ID and OTP are required for verification." });
    }

    const pool = await getDbPool(res);
    if (!pool) return;
    
  try {
    // 1. Check for a valid, unused, unexpired OTP
    const result = await pool.request()
      .input("userId", sql.Int, userId) 
      .input("otp", sql.Int, otp)     
      .query(`
        SELECT TOP 1 id
        FROM dbo.OTPs
        WHERE user_id=@userId 
          AND otp_code=@otp 
          AND is_verified=0                           
          AND created_at > DATEADD(minute, -5, GETDATE())
        ORDER BY id DESC
      `);

    if (!result.recordset.length) {
      return res.status(400).json({ success: false, message: "Invalid, expired, or already used OTP" });
    }

    // 2. Mark the specific OTP entry as verified/used in dbo.OTPs (is_verified = 1)
    const otpId = result.recordset[0].id;
    
    await pool.request()
      .input("id", sql.Int, otpId)
      .query(`UPDATE dbo.OTPs SET is_verified=1 WHERE id=@id`);
    
    // 🛑 IMPORTANT: NO UPDATE to dbo.Users here, matching your required flow.

    res.json({ success: true, message: "OTP verified successfully. Authorization is maintained." });
    
  } catch (err) {
    console.error("Verify OTP error:", err);
    res.status(500).json({ success: false, message: "Server error during verification" });
  }
});

// --- STEP 5: SEND SMS (Post-Verification/Authorization Check) ---
app.post("/api/send-sms", async (req, res) => {
  // Authorization check is done by frontend using Users.is_verified=1 set in Step 1
  const { to, message, twilioData } = req.body; 
  
  if (!twilioData || !twilioData.sid || !to || !message) {
     return res.status(400).json({ success: false, message: "Missing required data for SMS." });
  }

  try {
    // Send SMS
    const { sid, token, from } = twilioData;
    const client = twilio(sid, token);
    await client.messages.create({ from, to, body: message });

    res.json({ success: true, message: "SMS sent successfully" });

  } catch (err) {
    console.error("Send SMS error:", err);
    res.status(500).json({ success: false, message: "Server error or Twilio failed to send SMS" });
  }
});


// --- STEP 6: RESET VERIFICATION (Sets Users.is_verified = 0) ---
// Condition: is_verified must be FALSE after the session/logout/reset. (Step 5 -> Step 1)
app.post('/api/reset-verification', async (req, res) => {
    const { userId } = req.body; 

    if (!userId) {
        return res.status(400).json({ success: false, message: 'User ID is required for verification reset.' });
    }

    const pool = await getDbPool(res);
    if (!pool) return;
    
    try {
        const request = pool.request(); 
        request.input('userId', sql.Int, userId); 

        // CRITICAL: Set Users.is_verified = 0 for the user
        const query = `
            UPDATE dbo.Users 
            SET is_verified = 0 
            WHERE id = @userId;
        `;
        
        const result = await request.query(query); 

        if (result.rowsAffected[0] > 0) {
            console.log(`[RESET SUCCESS] User ID ${userId} verification status reset to 0 (FALSE).`);
        } else {
            console.warn(`[RESET FAILED] No rows affected for User ID ${userId}.`);
        }
        
        res.json({ success: true, message: 'Reset complete.' });

    } catch (error) {
        console.error('[DB ERROR] Database Error during verification reset:', error); 
        res.status(500).json({ success: false, message: 'Server error during verification reset.' });
    }
});

/* ================= START SERVER ================= */

app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);