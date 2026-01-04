
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import twilio from 'twilio';
import axios from "axios";
import multer from 'multer';
import fs from "fs";
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.json()); // Parses JSON from client
app.use(express.urlencoded({ extended: true })); // Required for TwiML endpoint
const API_VERSION = 'v22.0';
import mime from 'mime-types';

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

////////////webhook RAW Payload///////
app.post("/webhook", (req, res) => {
  console.log(
    "📩 RAW WEBHOOK PAYLOAD:\n",
    JSON.stringify(req.body, null, 2)
  );
  res.sendStatus(200);
});
/////////////////////////////////////

// -------------------------------
// 2. GLOBAL MIDDLEWARE
// -------------------------------
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3001"
];

app.use(
  cors({
    origin: function (origin, callback) {
      // allow REST tools like Postman
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("CORS not allowed"));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// -------------------------------
// 3. DEBUG LOGGER
// -------------------------------
app.use((req, _res, next) => {
  if (req.method === "POST") {
    console.log("--------------------------------------------------");
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    console.log(JSON.stringify(req.body, null, 2));
    console.log("--------------------------------------------------");
  }
  next();
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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


// Setup Multer to handle file uploads, saving to the 'uploads' folder
const upload2 = multer({ dest: "uploads/" });

// Middleware setup

app.use(express.json()); // For parsing application/json (not used for this specific endpoint, but good practice)

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

// The endpoint the React frontend calls
app.post("/upload1", upload2.single("file"), async (req, res) => {
  // Get dynamic inputs
  const appId = req.headers["x-app-id"]; // From custom header
  const { accessToken } = req.body;      // From form-data body

  if (!appId || !accessToken || !req.file) {
    return res.status(400).json({ error: "App ID, Access Token, and file are required" });
  }

  // File metadata from Multer
  const { path, originalname, mimetype, size } = req.file;
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
    
    // --- STEP 2: Upload file binary ---
    const fileBuffer = fs.readFileSync(path); // Read the temporary file into a buffer

    const uploadRes = await axios.post(
      `https://graph.facebook.com/v24.0/${uploadId}`, // Use the session ID
      fileBuffer, // Pass the raw binary buffer as the body
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

    // --- Cleanup and Final Response ---
    fs.unlinkSync(path); // MANDATORY: Delete the temporary file from the 'uploads' folder

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
    
    // Clean up temporary file even on error
    if (fs.existsSync(path)) {
        fs.unlinkSync(path);
    }
    
    // Return the error to the React frontend
    return res.status(500).json({
      error: error.response?.data || error.message
    });
  }
});


// -------------------------------
// 5. HELPERS
// -------------------------------
const normalize = (n = '') =>
  typeof n === 'string'
    ? n.replace(/\s+/g, '').replace(/^\+/, '')
    : '';

const sendWhatsAppText = async (to, text) => {
  await axios.post(
    CONFIG.WHATSAPP_API,
    {
      messaging_product: 'whatsapp',
      to,
      type: 'text',
      text: { body: text },
    },
    {
      headers: {
        Authorization: `Bearer ${CONFIG.ACCESS_TOKEN}`,
        'Content-Type': 'application/json',
      },
    }
  );
};

// ✅ Event handler
app.post('/webhook', async (req, res) => {
  try {
    if (req.body.object !== 'whatsapp_business_account') {
      return res.json({ status: 'IGNORED' });
    }

    for (const entry of req.body.entry || []) {
      for (const change of entry.changes || []) {
        for (const msg of change?.value?.messages || []) {
          const from = normalize(msg.from);
          const reply =
            msg.text?.body ||
            msg.button?.payload ||
            msg.interactive?.button_reply?.id;

          console.log(`📩 Incoming from ${from}:`, reply);

          if (!reply) continue;
          if (!allowedReplyNumbers.has(from)) {
            console.log(`⛔ Auto-reply blocked for ${from}`);
            continue;
          }

          rsvpResponses[from] = reply;

          await sendWhatsAppText(
            msg.from,
            `✅ Thank you for your response: "${reply}". We’ll contact you shortly 😊`
          );
        }
      }
    }

    res.json({ status: 'EVENT_RECEIVED' });
  } catch (err) {
    console.error('Webhook error:', err.message);
    res.sendStatus(500);
  }
});
///////////////////////Autoreply Watsup Messages //////////////////////////
// In-memory store of numbers allowed for auto-reply

app.use(bodyParser.json({ limit: '1mb' }));

/////////////////////////// watsup OTP Authentication ///////////////
app.use(bodyParser.json());

const TOKEN_STORE = {};

///////////////////////////// Send template message(pdf,image both send to watsup)/////////////////////
//Configure Multer to store files in memory (essential for reading file.buffer)
const upload = multer({ storage: multer.memoryStorage() }); 

// POST /api/upload-media: REWRITTEN UPLOAD LOGIC
// ----------------------------------------------------------------------
app.post('/api/upload-media', 
    // Step 1: Diagnostic Middleware (Runs before Multer)
    (req, res, next) => {
        console.log("--- DEBUG: Pre-Multer Check ---");
        console.log("Content-Type Header:", req.headers['content-type']); 
        // We MUST see 'multipart/form-data; boundary=...' here.
        next();
    }, 
    // Step 2: Multer File Handling
    upload.single('file'), 
    // Step 3: Main Route Handler
       // --- In server.js, inside app.post('/api/upload-media', ...) ---

async (req, res) => {
    try {
        const { phoneNumberId, accessToken, type } = req.body;
        const file = req.file;

        // ... (DEBUG checks here) ...

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded.' });
        }
        if (!phoneNumberId || !accessToken) {
             return res.status(400).json({ error: 'Missing configuration fields.' });
        }

        // 1. Determine the MIME type (Defensive rewrite)
        let mimeType = file.mimetype; 
        
        if (!mimeType && typeof mime.lookup === 'function') {
             // Use mime-types library if Multer didn't set it
             mimeType = mime.lookup(file.originalname);
        }
        
        // Final fallback if all else fails
        if (!mimeType) {
            mimeType = (type === 'document' ? 'application/pdf' : 'image/jpeg');
        }


        // 2. Prepare the request body for the WhatsApp API using form-data
        const formData = new FormData();
        formData.append('file', file.buffer, { filename: file.originalname, contentType: mimeType });
        formData.append('messaging_product', 'whatsapp');
        formData.append('type', mimeType); 

        
        // 3. Send the request to the WhatsApp Cloud API
        const response = await axios.post(
            `https://graph.facebook.com/v22.0/${phoneNumberId}/media`,
            formData,
            { 
                headers: { 
                    Authorization: `Bearer ${accessToken}`, 
                    ...formData.getHeaders() 
                },
                maxContentLength: Infinity, 
                maxBodyLength: Infinity,
            }
        );

        res.json({ mediaId: response.data.id });

    } catch (err) {
        // This should now catch ANY error, even a ReferenceError during execution
        console.error('FINAL Media Upload Error:', err.response?.data || err.message);
        res.status(500).json({ 
            error: 'Media upload failed at Graph API stage.', 
            details: err.response?.data || { message: err.message }
        });
    }
}
);

app.post('/api/send-message', async (req, res) => {
    try {
        const { 
            phoneNumber, 
            mediaId, 
            mediaType, 
            phoneNumberId, 
            accessToken,
            documentTemplateName,
            imageTemplateName,
            recipientName, 
            invoiceNumber  
        } = req.body;

        const templateName = mediaType === 'document' ? documentTemplateName : imageTemplateName;
        const componentType = mediaType === 'document' ? 'document' : 'image';
        
        // 1. Initialize Components array with the mandatory HEADER component
        const components = [
            // HEADER Component (for both Document and Image)
            {
                type: 'header',
                parameters: [
                    {
                        type: componentType,
                        [componentType]: { 
                            id: mediaId,
                            // Only include filename for documents
                            ...(mediaType === 'document' && { filename: 'Media_File.pdf' }) 
                        },
                    },
                ],
            },
        ];

        // 2. 🛑 CONDITIONAL FIX: Add the BODY component ONLY for Documents
        if (mediaType === 'document') {
            components.push({
                type: 'body',
                parameters: [
                    // Parameter 1: Recipient Name ({{1}})
                    {
                        type: 'text',
                        text: recipientName || 'Customer', 
                    },
                    // Parameter 2: Invoice Number ({{2}})
                    {
                        type: 'text',
                        text: invoiceNumber || 'INV-0001', 
                    }
                ],
            });
        }
        
        const data = {
            messaging_product: 'whatsapp',
            recipient_type: 'individual',
            to: phoneNumber,
            type: 'template',
            template: {
                name: templateName,
                language: { code: 'en' },
                components: components, // Use the dynamically built array
            },
        };

        const url = `https://graph.facebook.com/v22.0/${phoneNumberId}/messages`;
        const headers = {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
        };

        const response = await axios.post(url, data, { headers });
        res.json({ messageId: response.data.messages?.[0]?.id });

    } catch (err) {
        console.error('Message Send Error:', err.response?.data || err.message);
        res.status(500).json({ 
            error: 'Message sending failed at Graph API stage.', 
            details: err.response?.data || { message: err.message } 
        });
    }
});
///////////////////////////////////Autoreply///////////////////////////////////
// Webhook Event Handler: Receives incoming messages and other events from WhatsApp///////////
/* ================= CREATE TEMPLATE ================= */
/* ================= UTIL ================= */
function parseTemplate(text) {
  const variables = [];
  let index = 1;

  const parsedText = text.replace(/{(.*?)}/g, (_, v) => {
    variables.push(v);
    return `{{${index++}}}`;
  });

  return { parsedText, variables };
}
const allowedReplyMap = new Map();
/* ================= CREATE TEMPLATE ================= */
app.post("/api/create-template04", async (req, res) => {
  try {
    const { accessToken, wabaId, templateName, components } = req.body;
    if (!accessToken || !wabaId || !templateName || !components) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const bodyComponent = components.find(c => c.type === "BODY");
    if (!bodyComponent || !bodyComponent.text) {
      return res.status(400).json({ error: "Missing BODY text in components" });
    }

    const { parsedText, variables } = parseTemplate(bodyComponent.text);

    const examples = variables.length
      ? variables.map(v => {
          if (v === "name") return "John";
          if (v === "message") return "I am interested";
          return "Sample";
        })
      : [bodyComponent.text]; // fallback for static text

    const payload = {
      name: templateName,
      language: "en_US",
      category: "UTILITY",
      components: [
        {
          type: "BODY",
          text: parsedText
        }
      ]
    };

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

    res.json({ success: true, parsedText, variables, examples, apiResponse: response.data });

  } catch (err) {
    console.error("WhatsApp API ERROR:", JSON.stringify(err.response?.data, null, 2));
    res.status(500).json({ error: err.response?.data || err.message });
  }
});


/* ================= SEND TEMPLATE ================= */
app.post('/api/send-messages01', async (req, res) => {
  try {
    const {phoneNumbers, autoReplyMessage,accessToken ,templateName,phoneNumberId} = req.body;

    if (!phoneNumbers || phoneNumbers.length === 0 || !autoReplyMessage) {
      return res.status(400).json({
        success: false,
        error: 'message, phoneNumbers, and autoReplyMessage are required'
      });
    }
      // 2️⃣ Update allowedReplyMap with all numbers from frontend
  phoneNumbers.forEach((num) => {
    const normalized = normalizePhoneNumber(num);
    console.log('Adding to allowedReplyMap:', normalized);
    allowedReplyMap.set(normalized, { message: autoReplyMessage, templateName });
  });

    const results = [];

    for (const number of phoneNumbers) {
      const normalizedNumber = normalizePhoneNumber(number);
      if (!normalizedNumber) continue;

      try {
        await axios.post(
          `https://graph.facebook.com/v22.0/${phoneNumberId}/messages`,
          {
            messaging_product: 'whatsapp',
            to: normalizedNumber,
            type: 'text',
            text: { body:autoReplyMessage }
          },
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
              'Content-Type': 'application/json'
            }
          }
        );

        // ✅ STORE AUTO-REPLY MESSAGE FOR THIS NUMBER
       allowedReplyMap.set(normalizedNumber, { message: autoReplyMessage, templateName:templateName });


        results.push({ number: normalizedNumber, success: true });
      } catch (err) {
        results.push({
          number: normalizedNumber,
          success: false,
          error: err.response?.data?.error?.message
        });
      }
    }

    console.log('Updated auto-reply map:', [...allowedReplyMap.entries()]);

    res.json({ success: true, results });

  } catch (error) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});


// Map of phone numbers to auto-reply messages
const allowedReplyMap2 = new Map();

const normalizePhoneNumber = (num) =>
  typeof num === 'string' ? num.replace(/\s/g, '').replace(/^\+/, '') : '';
app.use(bodyParser.urlencoded({ extended: true }));

// Webhook endpoint
app.post('/webhook', async (req, res) => {
  try {
    // Only handle WhatsApp events
    if (req.body.object !== 'whatsapp_business_account') {
      return res.sendStatus(200);
    }

    const entries = req.body.entry || [];

    for (const entry of entries) {
      const changes = entry.changes || [];

      for (const change of changes) {
        if (change.field !== 'messages') continue;

        const phoneNumberId = change.value.metadata.phone_number_id; // ✅ correct
        const messages = change.value.messages || [];

        for (const msg of messages) {
          const from = normalizePhoneNumber(msg.from);
          const receivedText = msg.text?.body;
          if (!receivedText) continue;

          console.log(`Incoming message from ${from}: ${receivedText}`);

          // Get auto-reply message from your map
          const replyMessage = allowedReplyMap2.get(from);
          if (!replyMessage) {
            console.log(`No auto-reply configured for ${from}`);
            continue;
          }

          try {
            await axios.post(
              `https://graph.facebook.com/v22.0/${phoneNumberId}/messages`,
              {
                messaging_product: 'whatsapp',
                to: from,
                type: 'text',
                text: { body: replyMessage },
              },
              {
                headers: {
                  Authorization: `Bearer ${process.env.WHATSAPP_ACCESS_TOKEN}`,
                  'Content-Type': 'application/json',
                },
              }
            );

            console.log(`Auto-reply sent to ${from}`);
          } catch (sendError) {
            console.error(`Failed to send message to ${from}:`, sendError.response?.data || sendError.message);
          }
        }
      }
    }

    res.sendStatus(200); // ✅ respond quickly
  } catch (err) {
    console.error('Webhook processing error:', err);
    res.sendStatus(500);
  }
});





//////////////////////////////////// orderconformation Template///////////////////
// ------------------------
// Create WhatsApp Template
// ------------------------
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


// ------------------------
// Send Approved Template
app.post("/api/send-template03", async (req, res) => {
  try {
    const {
      phoneNumbers,
      templateName,
      phoneNumberId,
      accessToken,
      placeholders,
      documentHandle
    } = req.body;

    // Validation
    if (!phoneNumbers?.length || !templateName || !phoneNumberId || !accessToken) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const results = [];

    for (const number of phoneNumbers) {
      try {
        // Call WhatsApp API
        const response = await axios.post(
          `https://graph.facebook.com/v16.0/${phoneNumberId}/messages`,
          {
            messaging_product: "whatsapp",
            to: number,
            type: "template",
            template: {
              name: templateName,
              language: { code: "en_US" },
              components: [
                {
                  type: "body",
                  parameters: placeholders.map(p => ({ type: "text", text: p }))
                },
                documentHandle
                  ? {
                      type: "header",
                      parameters: [{ type: "document", document: { id: documentHandle } }]
                    }
                  : undefined
              ].filter(Boolean)
            }
          },
          {
            headers: { Authorization: `Bearer ${accessToken}` }
          }
        );
        results.push({ number, status: "sent", response: response.data });
      } catch (err) {
        console.error(`Failed to send to ${number}:`, err.response?.data || err.message);
        results.push({ number, status: "failed", error: err.response?.data || err.message });
      }
    }

    res.json({ success: true, results });
  } catch (err) {
    console.error("Error in /api/send-template03:", err);
    res.status(500).json({ error: err.message });
  }
});

//////////////////// watsup OTP verification ///////////////////////
// Generate formula-based OTP
// Formula-based OTP generator
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


//---------------- Send WhatsApp Location ----------------
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
/////////////////// pdf and image creation dynamic Template ///////////
/* ---------------- CREATE TEMPLATE with Header (Media) Body (Dynamic) Footer ---------------- */
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





// =======================================================
// 7. SEND WHATSAPP   marriage invitation MESSAGES 
// =======================================================
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
// Create Dynamic Template
// =======================
app.post("/api/create-template", async (req, res) => {
  try {
    const {
      template_name,
      h,                 // media handle
      num_placeholders,  // number of dynamic fields
      wabaId,
      accessToken,
      placeholders       // array of dynamic texts from frontend, e.g., ["John", "Jane", "25 Dec 2025", "Beach Resort"]
    } = req.body;

    if (!template_name || !h || !wabaId || !accessToken || !placeholders) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (placeholders.length !== num_placeholders) {
      return res
        .status(400)
        .json({ error: `Number of placeholders should be ${num_placeholders}` });
    }

    // Construct the body text dynamically with placeholders {{1}}, {{2}}, etc.
    const bodyText = `We are delighted to invite you to celebrate the wedding of {{1}} and {{2}}, which will take place on {{3}} at {{4}}. We hope to see you there!`;

    const payload = {
      name: template_name,
      language: "en_US",
      category: "MARKETING",
      components: [
        {
          type: "HEADER",
          format: "IMAGE",
          example: { header_handle: [h] }
        },
        {
          type: "BODY",
          text: bodyText,
          example: { body_text: [placeholders] } // <-- send dynamic values here
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
    console.error(err.response?.data || err);
    res.status(500).json({ error: err.response?.data || "Failed" });
  }
});


// =======================
// Send Template Messages
// =======================

const GRAPH_API = "https://graph.facebook.com/v22.0";

/* ---------------------------------------------------
   1️⃣ Upload Media → Get MEDIA ID from WhatsApp
--------------------------------------------------- */
const upload3 = multer({ dest: "uploads/" });

app.post("/api/upload-media", upload3.single("file"), async (req, res) => {
  try {
    const { phoneNumberId, accessToken } = req.body;
    if (!req.file || !phoneNumberId || !accessToken) {
      return res.status(400).json({ error: "Missing file or credentials" });
    }

    const formData = new FormData();
    formData.append("messaging_product", "whatsapp");
    formData.append("file", fs.createReadStream(req.file.path));
    formData.append("type", req.file.mimetype);

    const response = await axios.post(
      `https://graph.facebook.com/v20.0/${phoneNumberId}/media`,
      formData,
      { headers: { Authorization: `Bearer ${accessToken}`, ...formData.getHeaders() } }
    );

    fs.unlinkSync(req.file.path);

    res.json({ mediaId: response.data.id });
  } catch (err) {
    console.error(err.response?.data || err);
    res.status(500).json({ error: err.response?.data || err.message });
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
    for (const to of cleanNumbers) {
      const payload = {
        messaging_product: "whatsapp",
        to,
        type: "template",
        template: {
          name: templateName,
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
            }
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



// Webhook Event Handler (POST request)
// Meta sends POST requests to this endpoint for incoming messages and other events.
app.post('/webhook', async (req, res) => {
    console.log('Webhook event received. Processing...');
    try {
        if (req.body.object === 'whatsapp_business_account' && req.body.entry && req.body.entry.length > 0) {
            for (const entry of req.body.entry) {
                for (const change of entry.changes) {
                    if (change.field === 'messages' && change.value.messages && change.value.messages.length > 0) {
                        for (const message of change.value.messages) {
                            const rawFrom = message.from; // The sender's raw phone number
                            const from = normalizePhoneNumber(rawFrom); // Normalized sender number
                            const receivedMessageBody = message.text?.body; // Text message content

                            // Correctly extract payload and title for 'button' type messages
                            const interactiveReplyPayload = message.button?.payload; // For button clicks
                            const interactiveReplyTitle = message.button?.text;     // For button clicks

                            console.log(`[Webhook] Raw 'from': ${rawFrom}, Normalized: ${from}`);
                            console.log(`[Webhook] Body: "${receivedMessageBody || 'N/A'}", Payload: "${interactiveReplyPayload || 'N/A'}", Title: "${interactiveReplyTitle || 'N/A'}"`);
                            console.log(`[Webhook] Allowed numbers:`, Array.from(allowedReplyNumbers));

                            let autoReplySent = false;

                            // Handle Quick Reply Button Clicks (e.g., RSVP responses)
                            if (interactiveReplyPayload && allowedReplyNumbers.has(from)) {
                                console.log(`[Webhook] Received interactive reply from ${from}: ${interactiveReplyTitle} (Payload: ${interactiveReplyPayload})`);
                                rsvpResponses[from] = interactiveReplyPayload; // Store the RSVP response
                                console.log(`[Webhook] Stored RSVP for ${from}: ${interactiveReplyPayload}`);

                                let replyMessage;
                                // These payloads MUST match what you configured in Meta for your quick reply buttons.
                                switch (interactiveReplyPayload) {
                                    case 'Yes': // FIX: Changed payload to match the exact string from logs (assuming 'Yes' for consistency)
                                        replyMessage = `Wonderful! Thank you for confirming you'll attend. We look forward to celebrating with you! 🎉`;
                                        break;
                                    case 'No': // FIX: Changed payload to match the exact string from logs
                                        replyMessage = `We're sorry to hear you can't make it, but thank you for letting us know.`;
                                        break;
                                    case 'Will-Confirm-Later': // Confirmed from previous logs
                                        replyMessage = `Thank you for your response. Please let us know if your plans change.`;
                                        break;
                                    default:
                                        console.warn(`[Webhook] Unrecognized payload in switch: "${interactiveReplyPayload}" from ${from}`);
                                        replyMessage = `Thank you for your response: "${interactiveReplyTitle}". Our team will get back to you soon! 😊`;
                                }

                                // Send the auto-reply message back to the user
                                await axios.post(
                                    `https://graph.facebook.com/v22.0/${CONFIG.PHONE_NUMBER_ID}/messages`,
                                    {
                                        messaging_product: 'whatsapp',
                                        to: rawFrom, // Send back to the original sender
                                        type: 'text',
                                        text: { body: replyMessage }
                                    },
                                    {
                                        headers: {
                                            'Authorization': `Bearer ${CONFIG.ACCESS_TOKEN}`,
                                            'Content-Type': 'application/json'
                                        }
                                    }
                                );
                                console.log(`Auto-reply sent to ${rawFrom} for interactive response.`);
                                autoReplySent = true;
                            }
                            // Handle regular text messages (if the number is in allowedReplyNumbers and no auto-reply was sent yet)
                            else if (receivedMessageBody && allowedReplyNumbers.has(from) && !autoReplySent) {
                                console.log(`[Webhook] Number ${from} FOUND in allowedReplyNumbers (text message). Sending generic auto-reply.`);
                                const replyMessage = `Thank you for your response: "${receivedMessageBody}". Our team will get back to you soon! 😊`;
                                await axios.post(
                                    `https://graph.facebook.com/v22.0/${CONFIG.PHONE_NUMBER_ID}/messages`,
                                    {
                                        messaging_product: 'whatsapp',
                                        to: rawFrom,
                                        type: 'text',
                                        text: { body: replyMessage }
                                    },
                                    { headers: { 'Authorization': `Bearer ${CONFIG.ACCESS_TOKEN}`, 'Content-Type': 'application/json' } }
                                );
                            } else if (!autoReplySent) {
                                console.log(`[Webhook] No auto-reply for ${from}. Reason: Not found in allowedReplyNumbers or not a relevant message type.`);
                            }
                        }
                    } else {
                        console.log('Received non-message webhook event or unsupported change field:', JSON.stringify(change, null, 2));
                    }
                }
            }
            // Acknowledge the event receipt to Meta
            return res.status(200).json({ status: 'EVENT_RECEIVED', message: 'Webhook event processed.' });
        }
        console.log('Received unknown or non-WhatsApp webhook event:', JSON.stringify(req.body, null, 2));
        return res.status(200).json({ status: 'IGNORED', message: 'Unknown or non-WhatsApp event.' });
    } catch (error) {
        console.error('Error processing webhook event:', error.response?.data || error.message);
        return res.status(500).json({ success: false, error: 'Failed to process webhook event.' });
    }
});



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


/* ---------------- CREATE TEMPLATE audio,video, ---------------- */
app.post("/api/create-template1", async (req, res) => {
  try {
    const {
      template_name,
      media_type,    // "image", "document", "audio", "video"
      h,             // MEDIA_ID from upload
      placeholders,  // Array of dynamic texts ["John", "Jane", "25 Dec 2025"]
      wabaId,
      accessToken
    } = req.body;

    if (!template_name || !media_type || !h || !wabaId || !accessToken) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Example body text with placeholders {{1}}, {{2}}, etc.
    const bodyText = `Hello {{1}}, your {{2}} is ready. Please check it.`;

    const components = [
      {
        type: "HEADER",
        format: media_type.toUpperCase(), // IMAGE, DOCUMENT, AUDIO, VIDEO
        example: { header_handle: [h] }
      },
      {
        type: "BODY",
        text: bodyText,
        example: { body_text: [placeholders] } 
      }
    ];

    const payload = {
      name: template_name,
      language: "en_US",
      category: "MARKETING",
      components
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

    res.json({ success: true, template: response.data });
  } catch (err) {
    console.error("Template creation error:", err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || "Failed to create template" });
  }
});

/* ---------------- SEND MESSAGES ---------------- */
app.post('/api/send-messages1', async (req, res) => {
  try {
    const { phoneNumbers, template_name, placeholder_values, h, media_type, phoneNumberId, accessToken } = req.body;

    if (!phoneNumbers || !placeholder_values || !h) {
      return res.status(400).json({ error: 'Required fields missing' });
    }

    const results = [];

    for (const number of phoneNumbers) {
      const payload = {
        messaging_product: 'whatsapp',
        to: number,
        type: 'template',
        template: {
          name: template_name,
          language: { code: 'en_US' },
          components: [
            {
              type: 'header',
              parameters: [{ [media_type]: { id: h } }]
            },
            {
              type: 'body',
              parameters: placeholder_values.map(v => ({ type: 'text', text: v }))
            }
          ]
        }
      };

      try {
        await axios.post(`https://graph.facebook.com/v22.0/${phoneNumberId}/messages`, payload, {
          headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        });
        results.push({ number, success: true });
      } catch (err) {
        results.push({ number, success: false, error: err.response?.data?.error?.message || err.message });
      }
    }

    res.json({ success: true, results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(5000, () => console.log('Server running on port 5000'));


// =======================================================
// 11. START SERVER
// =======================================================
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  console.log(`📡 Webhook URL: http://localhost:${PORT}/webhook`);
});
