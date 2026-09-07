require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const axios = require("axios");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const UPLOAD_DIR = path.join(PUBLIC_DIR, "uploads", "products");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* =========================================================
   EXPRESS
========================================================= */

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "CHANGE_THIS_SECRET_IN_RENDER",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

app.use("/uploads", express.static(path.join(PUBLIC_DIR, "uploads")));

app.use(express.static(PUBLIC_DIR));

/* =========================================================
   DATABASE
========================================================= */

const db = new Database(
  process.env.DB_PATH || path.join(ROOT, "darkweb.db")
);

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  price_kes REAL NOT NULL,
  binance_price TEXT DEFAULT '',
  delivery_content TEXT DEFAULT '',
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_number TEXT UNIQUE NOT NULL,
  user_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  amount_kes REAL NOT NULL,
  amount_crypto TEXT DEFAULT '',
  payment_method TEXT NOT NULL,
  payment_status TEXT DEFAULT 'PENDING',
  delivery_method TEXT NOT NULL,
  delivery_target TEXT NOT NULL,
  phone TEXT DEFAULT '',
  binance_txid TEXT DEFAULT '',
  binance_verified INTEGER DEFAULT 0,
  checkout_request_id TEXT DEFAULT '',
  merchant_request_id TEXT DEFAULT '',
  mpesa_receipt TEXT DEFAULT '',
  delivery_status TEXT DEFAULT 'RECEIVED',
  delivery_notes TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  paid_at TEXT DEFAULT '',
  delivered_at TEXT DEFAULT ''
);
`);

/* =========================================================
   DATABASE MIGRATION
========================================================= */

function addColumnIfMissing(table, column, definition) {
  const columns = db
    .prepare(`PRAGMA table_info(${table})`)
    .all();

  const exists = columns.some((c) => c.name === column);

  if (!exists) {
    db.prepare(
      `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
    ).run();

    console.log(`Added column ${table}.${column}`);
  }
}

addColumnIfMissing("products", "image_url", "TEXT");

/* =========================================================
   DEFAULT ADMIN
========================================================= */

const adminEmail =
  process.env.ADMIN_EMAIL || "admin@example.com";

const adminPassword =
  process.env.ADMIN_PASSWORD || "ChangeMe123!";

const existingAdmin = db
  .prepare("SELECT id FROM users WHERE email = ?")
  .get(adminEmail);

if (!existingAdmin) {
  const passwordHash = bcrypt.hashSync(adminPassword, 12);

  db.prepare(`
    INSERT INTO users
    (name, email, password_hash, is_admin)
    VALUES (?, ?, ?, 1)
  `).run(
    "Administrator",
    adminEmail,
    passwordHash
  );

  console.log("Admin account created:", adminEmail);
}

/* =========================================================
   SAMPLE PRODUCTS
========================================================= */

const productCount = db
  .prepare("SELECT COUNT(*) AS count FROM products")
  .get().count;

if (productCount === 0) {
  const insert = db.prepare(`
    INSERT INTO products
    (name, description, price_kes, binance_price, delivery_content, active)
    VALUES (?, ?, ?, ?, ?, 1)
  `);

  const products = [
    [
      "Item 1",
      "Digital product Item 1",
      500,
      "3.50",
      "Replace this with your Item 1 delivery content."
    ],
    [
      "Item 2",
      "Digital product Item 2",
      1000,
      "7.00",
      "Replace this with your Item 2 delivery content."
    ],
    [
      "Item 3",
      "Digital product Item 3",
      1500,
      "10.50",
      "Replace this with your Item 3 delivery content."
    ],
    [
      "Item 4",
      "Digital product Item 4",
      2500,
      "17.50",
      "Replace this with your Item 4 delivery content."
    ],
    [
      "Item 5",
      "Digital product Item 5",
      5000,
      "35.00",
      "Replace this with your Item 5 delivery content."
    ]
  ];

  for (const p of products) {
    insert.run(...p);
  }

  console.log("Sample products created.");
}

/* =========================================================
   IMAGE UPLOAD
========================================================= */

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR);
  },

  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();

    const safeName =
      Date.now() +
      "-" +
      crypto.randomBytes(8).toString("hex") +
      ext;

    cb(null, safeName);
  }
});

const upload = multer({
  storage,

  limits: {
    fileSize: 5 * 1024 * 1024
  },

  fileFilter: function (req, file, cb) {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif"
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(
        new Error(
          "Only JPG, PNG, WEBP and GIF images are allowed."
        )
      );
    }

    cb(null, true);
  }
});

/* =========================================================
   HELPERS
========================================================= */

function generateOrderNumber() {
  return (
    "DW-" +
    Date.now().toString(36).toUpperCase() +
    "-" +
    crypto.randomBytes(3).toString("hex").toUpperCase()
  );
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.is_admin) {
    return res.status(403).json({
      error: "Admin access required"
    });
  }

  next();
}

/* =========================================================
   AUTH
========================================================= */

app.post("/api/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Name, email and password are required."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must contain at least 6 characters."
      });
    }

    const normalizedEmail =
      String(email).trim().toLowerCase();

    const exists = db
      .prepare("SELECT id FROM users WHERE email = ?")
      .get(normalizedEmail);

    if (exists) {
      return res.status(409).json({
        error: "Email already registered."
      });
    }

    const passwordHash = await bcrypt.hash(
      password,
      12
    );

    const result = db.prepare(`
      INSERT INTO users
      (name, email, password_hash)
      VALUES (?, ?, ?)
    `).run(
      String(name).trim(),
      normalizedEmail,
      passwordHash
    );

    req.session.user = {
      id: result.lastInsertRowid,
      name: String(name).trim(),
      email: normalizedEmail,
      is_admin: 0
    };

    res.json({
      success: true,
      user: req.session.user
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed."
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    const normalizedEmail =
      String(email || "").trim().toLowerCase();

    const user = db
      .prepare(`
        SELECT *
        FROM users
        WHERE email = ?
      `)
      .get(normalizedEmail);

    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const valid = await bcrypt.compare(
      password || "",
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      is_admin: Number(user.is_admin)
    };

    res.json({
      success: true,
      user: req.session.user
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true
    });
  });
});

app.get("/api/me", (req, res) => {
  res.json({
    user: req.session.user || null
  });
});

/* =========================================================
   PRODUCTS
========================================================= */

app.get("/api/products", (req, res) => {
  const products = db
    .prepare(`
      SELECT
        id,
        name,
        description,
        price_kes,
        binance_price,
        image_url,
        active,
        created_at
      FROM products
      WHERE active = 1
      ORDER BY id DESC
    `)
    .all();

  res.json({
    products
  });
});

/* =========================================================
   ADMIN PRODUCTS
========================================================= */

app.get(
  "/api/admin/products",
  requireAdmin,
  (req, res) => {
    const products = db
      .prepare(`
        SELECT *
        FROM products
        ORDER BY id DESC
      `)
      .all();

    res.json({
      products
    });
  }
);

/*
   ADD PRODUCT WITH IMAGE

   multipart/form-data:
   name
   description
   price_kes
   binance_price
   delivery_content
   image
*/

app.post(
  "/api/admin/products",
  requireAdmin,
  upload.single("image"),
  (req, res) => {
    try {
      const {
        name,
        description,
        price_kes,
        binance_price,
        delivery_content
      } = req.body;

      if (!name || !price_kes) {
        if (req.file) {
          fs.unlinkSync(req.file.path);
        }

        return res.status(400).json({
          error: "Product name and M-Pesa price are required."
        });
      }

      const price = Number(price_kes);

      if (!Number.isFinite(price) || price <= 0) {
        if (req.file) {
          fs.unlinkSync(req.file.path);
        }

        return res.status(400).json({
          error: "Invalid product price."
        });
      }

      let imageUrl = "";

      if (req.file) {
        imageUrl =
          "/uploads/products/" +
          req.file.filename;
      }

      const result = db.prepare(`
        INSERT INTO products
        (
          name,
          description,
          price_kes,
          binance_price,
          delivery_content,
          image_url,
          active
        )
        VALUES (?, ?, ?, ?, ?, ?, 1)
      `).run(
        String(name).trim(),
        String(description || "").trim(),
        price,
        String(binance_price || "").trim(),
        String(delivery_content || "").trim(),
        imageUrl
      );

      const product = db
        .prepare(`
          SELECT *
          FROM products
          WHERE id = ?
        `)
        .get(result.lastInsertRowid);

      res.json({
        success: true,
        product
      });
    } catch (error) {
      console.error(error);

      if (req.file) {
        try {
          fs.unlinkSync(req.file.path);
        } catch {}
      }

      res.status(500).json({
        error: error.message || "Product creation failed."
      });
    }
  }
);

/* =========================================================
   TOGGLE PRODUCT
========================================================= */

app.post(
  "/api/admin/products/:id/toggle",
  requireAdmin,
  (req, res) => {
    const id = Number(req.params.id);

    const product = db
      .prepare("SELECT * FROM products WHERE id = ?")
      .get(id);

    if (!product) {
      return res.status(404).json({
        error: "Product not found."
      });
    }

    const newStatus =
      product.active ? 0 : 1;

    db.prepare(`
      UPDATE products
      SET active = ?
      WHERE id = ?
    `).run(
      newStatus,
      id
    );

    res.json({
      success: true,
      active: newStatus
    });
  }
);

/* =========================================================
   DELETE PRODUCT
========================================================= */

app.delete(
  "/api/admin/products/:id",
  requireAdmin,
  (req, res) => {
    const id = Number(req.params.id);

    const product = db
      .prepare("SELECT * FROM products WHERE id = ?")
      .get(id);

    if (!product) {
      return res.status(404).json({
        error: "Product not found."
      });
    }

    if (product.image_url) {
      const imagePath = path.join(
        PUBLIC_DIR,
        product.image_url.replace(/^\/+/, "")
      );

      if (
        fs.existsSync(imagePath) &&
        imagePath.startsWith(PUBLIC_DIR)
      ) {
        try {
          fs.unlinkSync(imagePath);
        } catch {}
      }
    }

    db.prepare(`
      DELETE FROM products
      WHERE id = ?
    `).run(id);

    res.json({
      success: true
    });
  }
);

/* =========================================================
   CREATE ORDER
========================================================= */

app.post(
  "/api/orders",
  requireLogin,
  (req, res) => {
    try {
      const {
        product_id,
        payment_method,
        delivery_method,
        delivery_target,
        phone
      } = req.body;

      const product = db
        .prepare(`
          SELECT *
          FROM products
          WHERE id = ?
          AND active = 1
        `)
        .get(Number(product_id));

      if (!product) {
        return res.status(404).json({
          error: "Product not found."
        });
      }

      if (
        !["MPESA", "BINANCE"].includes(
          payment_method
        )
      ) {
        return res.status(400).json({
          error: "Invalid payment method."
        });
      }

      if (
        !["EMAIL", "WHATSAPP"].includes(
          delivery_method
        )
      ) {
        return res.status(400).json({
          error: "Invalid delivery method."
        });
      }

      if (!delivery_target) {
        return res.status(400).json({
          error: "Delivery target is required."
        });
      }

      const orderNumber =
        generateOrderNumber();

      const result = db.prepare(`
        INSERT INTO orders
        (
          order_number,
          user_id,
          product_id,
          amount_kes,
          amount_crypto,
          payment_method,
          payment_status,
          delivery_method,
          delivery_target,
          phone,
          delivery_status
        )
        VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, 'RECEIVED')
      `).run(
        orderNumber,
        req.session.user.id,
        product.id,
        product.price_kes,
        product.binance_price || "",
        payment_method,
        delivery_method,
        String(delivery_target).trim(),
        String(phone || "").trim()
      );

      const order = db
        .prepare(`
          SELECT *
          FROM orders
          WHERE id = ?
        `)
        .get(result.lastInsertRowid);

      res.json({
        success: true,
        order
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not create order."
      });
    }
  }
);

/* =========================================================
   CUSTOMER ORDERS
========================================================= */

app.get(
  "/api/orders",
  requireLogin,
  (req, res) => {
    const orders = db
      .prepare(`
        SELECT
          o.*,
          p.name AS product_name,
          p.image_url
        FROM orders o
        JOIN products p
          ON p.id = o.product_id
        WHERE o.user_id = ?
        ORDER BY o.id DESC
      `)
      .all(req.session.user.id);

    res.json({
      orders
    });
  }
);

/* =========================================================
   TRACK ORDER
========================================================= */

app.get(
  "/api/orders/:orderNumber",
  requireLogin,
  (req, res) => {
    const order = db
      .prepare(`
        SELECT
          o.*,
          p.name AS product_name,
          p.description,
          p.image_url
        FROM orders o
        JOIN products p
          ON p.id = o.product_id
        WHERE o.order_number = ?
        AND o.user_id = ?
      `)
      .get(
        req.params.orderNumber,
        req.session.user.id
      );

    if (!order) {
      return res.status(404).json({
        error: "Order not found."
      });
    }

    res.json({
      order
    });
  }
);

/* =========================================================
   M-PESA
========================================================= */

async function getMpesaToken() {
  const key =
    process.env.MPESA_CONSUMER_KEY;

  const secret =
    process.env.MPESA_CONSUMER_SECRET;

  if (!key || !secret) {
    throw new Error(
      "M-Pesa credentials are not configured."
    );
  }

  const environment =
    process.env.MPESA_ENV === "production"
      ? "production"
      : "sandbox";

  const base =
    environment === "production"
      ? "https://api.safaricom.co.ke"
      : "https://sandbox.safaricom.co.ke";

  const credentials = Buffer.from(
    `${key}:${secret}`
  ).toString("base64");

  const response = await axios.get(
    `${base}/oauth/v1/generate?grant_type=client_credentials`,
    {
      headers: {
        Authorization: `Basic ${credentials}`
      }
    }
  );

  return {
    token: response.data.access_token,
    base
  };
}

app.post(
  "/api/mpesa/stkpush",
  requireLogin,
  async (req, res) => {
    try {
      const {
        order_number,
        phone
      } = req.body;

      const order = db
        .prepare(`
          SELECT *
          FROM orders
          WHERE order_number = ?
          AND user_id = ?
        `)
        .get(
          order_number,
          req.session.user.id
        );

      if (!order) {
        return res.status(404).json({
          error: "Order not found."
        });
      }

      if (order.payment_method !== "MPESA") {
        return res.status(400).json({
          error: "This order is not using M-Pesa."
        });
      }

      const {
        token,
        base
      } = await getMpesaToken();

      const shortcode =
        process.env.MPESA_SHORTCODE;

      const passkey =
        process.env.MPESA_PASSKEY;

      const callback =
        process.env.MPESA_CALLBACK_URL;

      if (
        !shortcode ||
        !passkey ||
        !callback
      ) {
        return res.status(500).json({
          error:
            "M-Pesa environment variables are incomplete."
        });
      }

      const timestamp =
        new Date()
          .toISOString()
          .replace(/\D/g, "")
          .slice(0, 14);

      const password = Buffer.from(
        `${shortcode}${passkey}${timestamp}`
      ).toString("base64");

      const response =
        await axios.post(
          `${base}/mpesa/stkpush/v1/processrequest`,
          {
            BusinessShortCode: shortcode,
            Password: password,
            Timestamp: timestamp,
            TransactionType:
              "CustomerPayBillOnline",
            Amount: Math.round(
              order.amount_kes
            ),
            PartyA: phone,
            PartyB: shortcode,
            PhoneNumber: phone,
            CallBackURL: callback,
            AccountReference:
              order.order_number,
            TransactionDesc:
              `Payment for ${order.order_number}`
          },
          {
            headers: {
              Authorization:
                `Bearer ${token}`
            }
          }
        );

      db.prepare(`
        UPDATE orders
        SET checkout_request_id = ?,
            merchant_request_id = ?
        WHERE id = ?
      `).run(
        response.data.CheckoutRequestID || "",
        response.data.MerchantRequestID || "",
        order.id
      );

      res.json({
        success: true,
        message:
          response.data.CustomerMessage ||
          "Check your phone and enter your M-Pesa PIN.",
        data: response.data
      });
    } catch (error) {
      console.error(
        "M-Pesa error:",
        error.response?.data || error.message
      );

      res.status(500).json({
        error:
          error.response?.data?.errorMessage ||
          error.response?.data?.ResponseDescription ||
          error.message ||
          "M-Pesa request failed."
      });
    }
  }
);

/* =========================================================
   M-PESA CALLBACK
========================================================= */

app.post(
  "/api/mpesa/callback",
  (req, res) => {
    try {
      const body =
        req.body?.Body?.stkCallback;

      if (!body) {
        return res.json({
          ResultCode: 0,
          ResultDesc: "Accepted"
        });
      }

      const checkoutRequestId =
        body.CheckoutRequestID;

      const resultCode =
        Number(body.ResultCode);

      const metadata =
        body.CallbackMetadata?.Item || [];

      const getItem = (name) => {
        const item = metadata.find(
          (x) => x.Name === name
        );

        return item ? item.Value : "";
      };

      const receipt =
        getItem("MpesaReceiptNumber");

      const order = db
        .prepare(`
          SELECT *
          FROM orders
          WHERE checkout_request_id = ?
        `)
        .get(checkoutRequestId);

      if (order && resultCode === 0) {
        db.prepare(`
          UPDATE orders
          SET payment_status = 'PAID',
              mpesa_receipt = ?,
              paid_at = CURRENT_TIMESTAMP,
              delivery_status = 'PROCESSING'
          WHERE id = ?
        `).run(
          receipt || "",
          order.id
        );
      }

      if (order && resultCode !== 0) {
        db.prepare(`
          UPDATE orders
          SET payment_status = 'PAYMENT_FAILED'
          WHERE id = ?
        `).run(order.id);
      }

      res.json({
        ResultCode: 0,
        ResultDesc: "Accepted"
      });
    } catch (error) {
      console.error(
        "M-Pesa callback error:",
        error
      );

      res.json({
        ResultCode: 0,
        ResultDesc: "Accepted"
      });
    }
  }
);

/* =========================================================
   BINANCE PAYMENT INFO
========================================================= */

app.get(
  "/api/binance/payment-info",
  requireLogin,
  (req, res) => {
    res.json({
      asset:
        process.env.BINANCE_ASSET ||
        "USDT",

      network:
        process.env.BINANCE_NETWORK ||
        "TRC20",

      address:
        process.env.BINANCE_PAYMENT_ADDRESS ||
        "",

      instructions:
        "Send the exact amount shown for your order, then submit your transaction hash for verification."
    });
  }
);

/* =========================================================
   BINANCE SUBMISSION
========================================================= */

app.post(
  "/api/binance/submit",
  requireLogin,
  (req, res) => {
    try {
      const {
        order_number,
        txid
      } = req.body;

      if (!txid) {
        return res.status(400).json({
          error:
            "Transaction hash is required."
        });
      }

      const order = db
        .prepare(`
          SELECT *
          FROM orders
          WHERE order_number = ?
          AND user_id = ?
        `)
        .get(
          order_number,
          req.session.user.id
        );

      if (!order) {
        return res.status(404).json({
          error: "Order not found."
        });
      }

      db.prepare(`
        UPDATE orders
        SET binance_txid = ?,
            payment_status = 'PAYMENT_REVIEW'
        WHERE id = ?
      `).run(
        String(txid).trim(),
        order.id
      );

      res.json({
        success: true,
        message:
          "Transaction submitted for verification."
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Could not submit transaction."
      });
    }
  }
);

/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
  "/api/admin/orders",
  requireAdmin,
  (req, res) => {
    const orders = db
      .prepare(`
        SELECT
          o.*,
          p.name AS product_name,
          u.name AS customer_name,
          u.email AS customer_email
        FROM orders o
        JOIN products p
          ON p.id = o.product_id
        JOIN users u
          ON u.id = o.user_id
        ORDER BY o.id DESC
      `)
      .all();

    res.json({
      orders
    });
  }
);

/* =========================================================
   VERIFY BINANCE
========================================================= */

app.post(
  "/api/admin/orders/:id/verify-binance",
  requireAdmin,
  (req, res) => {
    const id = Number(req.params.id);

    const {
      approved
    } = req.body;

    const order = db
      .prepare(`
        SELECT *
        FROM orders
        WHERE id = ?
      `)
      .get(id);

    if (!order) {
      return res.status(404).json({
        error: "Order not found."
      });
    }

    if (approved) {
      db.prepare(`
        UPDATE orders
        SET payment_status = 'PAID',
            binance_verified = 1,
            paid_at = CURRENT_TIMESTAMP,
            delivery_status = 'PROCESSING'
        WHERE id = ?
      `).run(id);
    } else {
      db.prepare(`
        UPDATE orders
        SET payment_status = 'PAYMENT_FAILED',
            binance_verified = 0
        WHERE id = ?
      `).run(id);
    }

    res.json({
      success: true
    });
  }
);

/* =========================================================
   ADMIN DELIVERY
========================================================= */

app.post(
  "/api/admin/orders/:id/delivery",
  requireAdmin,
  (req, res) => {
    const id = Number(req.params.id);

    const {
      delivery_status,
      delivery_notes
    } = req.body;

    const allowed = [
      "RECEIVED",
      "PROCESSING",
      "DELIVERING",
      "DELIVERED"
    ];

    if (!allowed.includes(delivery_status)) {
      return res.status(400).json({
        error: "Invalid delivery status."
      });
    }

    const deliveredAt =
      delivery_status === "DELIVERED"
        ? new Date().toISOString()
        : "";

    db.prepare(`
      UPDATE orders
      SET delivery_status = ?,
          delivery_notes = ?,
          delivered_at = ?
      WHERE id = ?
    `).run(
      delivery_status,
      String(delivery_notes || ""),
      deliveredAt,
      id
    );

    res.json({
      success: true
    });
  }
);

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "DARK WEB STORE",
    time: new Date().toISOString()
  });
});

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.get("*splat", (req, res) => {
  res.sendFile(
    path.join(PUBLIC_DIR, "index.html")
  );
});

/* =========================================================
   MULTER ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        error:
          "Image is too large. Maximum size is 5MB."
      });
    }

    return res.status(400).json({
      error: error.message
    });
  }

  if (error) {
    return res.status(400).json({
      error: error.message
    });
  }

  next();
});

/* =========================================================
   START
========================================================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `DARK WEB STORE running on port ${PORT}`
  );

  console.log(
    `Products images: ${UPLOAD_DIR}`
  );
});
