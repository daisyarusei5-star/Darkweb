"use strict";

/* =========================================================
   DARK WEB STORE
   Complete Express + SQLite Backend
   Paystack + Binance Pay
   Admin Users + Orders + Products
   WhatsApp Support
   ========================================================= */

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

/* =========================================================
   APP CONFIG
   ========================================================= */

const app = express();

const PORT = Number(process.env.PORT || 3000);

const PUBLIC_DIR = path.join(__dirname, "public");

const UPLOAD_DIR = path.join(
  PUBLIC_DIR,
  "uploads",
  "products"
);

fs.mkdirSync(UPLOAD_DIR, {
  recursive: true
});

app.set("trust proxy", 1);

/* =========================================================
   ENVIRONMENT
   ========================================================= */

const ADMIN_EMAIL = String(
  process.env.ADMIN_EMAIL ||
  "admin@example.com"
)
  .trim()
  .toLowerCase();

const ADMIN_PASSWORD = String(
  process.env.ADMIN_PASSWORD ||
  "ChangeMe123!"
);

const SESSION_SECRET = String(
  process.env.SESSION_SECRET ||
  "CHANGE_THIS_SESSION_SECRET"
);

const PUBLIC_BASE_URL = String(
  process.env.PUBLIC_BASE_URL ||
  ""
)
  .trim()
  .replace(/\/+$/, "");

const SUPPORT_WHATSAPP = String(
  process.env.SUPPORT_WHATSAPP ||
  "254781601410"
)
  .replace(/\D/g, "");

const PAYSTACK_SECRET_KEY = String(
  process.env.PAYSTACK_SECRET_KEY ||
  ""
).trim();

const PAYSTACK_CURRENCY = String(
  process.env.PAYSTACK_CURRENCY ||
  "KES"
)
  .trim()
  .toUpperCase();

const PAYSTACK_CHANNELS = String(
  process.env.PAYSTACK_CHANNELS ||
  ""
)
  .split(",")
  .map(x => x.trim())
  .filter(Boolean);

const BINANCE_API_KEY = String(
  process.env.BINANCE_PAY_API_KEY ||
  ""
).trim();

const BINANCE_SECRET_KEY = String(
  process.env.BINANCE_PAY_SECRET_KEY ||
  ""
).trim();

const BINANCE_CURRENCY = String(
  process.env.BINANCE_PAY_CURRENCY ||
  "USDT"
)
  .trim()
  .toUpperCase();

const BINANCE_BASE_URL = String(
  process.env.BINANCE_PAY_BASE_URL ||
  "https://bpay.binanceapi.com"
)
  .trim()
  .replace(/\/+$/, "");

const DB_PATH = String(
  process.env.DB_PATH ||
  path.join(__dirname, "darkweb.db")
);

/* =========================================================
   VALIDATION
   ========================================================= */

if (ADMIN_PASSWORD.length < 6) {
  throw new Error(
    "ADMIN_PASSWORD must contain at least 6 characters."
  );
}

/* =========================================================
   DATABASE
   ========================================================= */

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

/* =========================================================
   DATABASE HELPERS
   ========================================================= */

function addColumnIfMissing(
  table,
  column,
  definition
) {
  const columns = db
    .prepare(`PRAGMA table_info(${table})`)
    .all();

  const exists = columns.some(
    c => c.name === column
  );

  if (!exists) {
    db.exec(
      `ALTER TABLE ${table}
       ADD COLUMN ${column} ${definition}`
    );
  }
}

/* =========================================================
   TABLES
   ========================================================= */

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    price_kes REAL NOT NULL DEFAULT 0,
    binance_price REAL DEFAULT 0,
    delivery_content TEXT DEFAULT '',
    image_url TEXT DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    order_number TEXT NOT NULL UNIQUE,

    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,

    amount_kes REAL NOT NULL DEFAULT 0,
    amount_crypto REAL DEFAULT 0,

    payment_method TEXT NOT NULL DEFAULT '',
    payment_status TEXT NOT NULL DEFAULT 'pending',

    delivery_method TEXT NOT NULL DEFAULT 'email',
    delivery_target TEXT NOT NULL DEFAULT '',
    phone TEXT DEFAULT '',

    paystack_reference TEXT DEFAULT '',
    paystack_transaction_id TEXT DEFAULT '',
    paystack_receipt TEXT DEFAULT '',

    binance_merchant_trade_no TEXT DEFAULT '',
    binance_prepay_id TEXT DEFAULT '',
    binance_transaction_id TEXT DEFAULT '',

    delivery_status TEXT NOT NULL DEFAULT 'pending',
    delivery_notes TEXT DEFAULT '',

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    paid_at TEXT DEFAULT '',
    delivered_at TEXT DEFAULT '',

    FOREIGN KEY(user_id)
      REFERENCES users(id),

    FOREIGN KEY(product_id)
      REFERENCES products(id)
  );
`);

/* =========================================================
   OLD DATABASE MIGRATIONS
   ========================================================= */

addColumnIfMissing(
  "products",
  "image_url",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "products",
  "binance_price",
  "REAL DEFAULT 0"
);

addColumnIfMissing(
  "orders",
  "paystack_reference",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "orders",
  "paystack_transaction_id",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "orders",
  "paystack_receipt",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "orders",
  "binance_merchant_trade_no",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "orders",
  "binance_prepay_id",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "orders",
  "binance_transaction_id",
  "TEXT DEFAULT ''"
);

/* =========================================================
   ADMIN ACCOUNT
   ========================================================= */

const adminHash = bcrypt.hashSync(
  ADMIN_PASSWORD,
  12
);

const existingAdmin = db
  .prepare(
    `SELECT *
     FROM users
     WHERE email = ?`
  )
  .get(ADMIN_EMAIL);

if (!existingAdmin) {
  db.prepare(`
    INSERT INTO users
      (name, email, password_hash, is_admin)
    VALUES
      (?, ?, ?, 1)
  `).run(
    "Administrator",
    ADMIN_EMAIL,
    adminHash
  );

  console.log(
    "ADMIN CREATED:",
    ADMIN_EMAIL
  );
} else {
  db.prepare(`
    UPDATE users
    SET
      password_hash = ?,
      is_admin = 1,
      name = 'Administrator'
    WHERE email = ?
  `).run(
    adminHash,
    ADMIN_EMAIL
  );

  console.log(
    "ADMIN UPDATED:",
    ADMIN_EMAIL
  );
}

/* =========================================================
   EXPRESS MIDDLEWARE
   ========================================================= */

app.use(
  express.json({
    limit: "2mb",

    verify: (
      req,
      res,
      buffer
    ) => {
      req.rawBody = Buffer.from(buffer);
    }
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "2mb"
  })
);

/* =========================================================
   SESSION
   ========================================================= */

app.use(
  session({
    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,

      sameSite: "lax",

      secure:
        process.env.NODE_ENV ===
        "production",

      maxAge:
        1000 *
        60 *
        60 *
        24 *
        7
    }
  })
);

/* =========================================================
   STATIC FILES
   ========================================================= */

app.use(
  "/uploads",
  express.static(
    path.join(
      PUBLIC_DIR,
      "uploads"
    )
  )
);

app.use(
  express.static(PUBLIC_DIR)
);

/* =========================================================
   GENERAL HELPERS
   ========================================================= */

function cleanEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function cleanText(value) {
  return String(value || "").trim();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
}

function isValidWhatsApp(value) {
  return /^\d{9,15}$/.test(
    String(value || "").replace(/\D/g, "")
  );
}

function makeOrderNumber() {
  return (
    "DW" +
    Date.now().toString() +
    crypto
      .randomBytes(4)
      .toString("hex")
      .toUpperCase()
  );
}

function makeBinanceTradeNo() {
  return (
    "DW" +
    Date.now().toString() +
    crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase()
  ).slice(0, 32);
}

function getBaseUrl(req) {
  if (PUBLIC_BASE_URL) {
    return PUBLIC_BASE_URL;
  }

  const protocol =
    req.headers["x-forwarded-proto"] ||
    req.protocol;

  const host =
    req.headers["x-forwarded-host"] ||
    req.get("host");

  return `${protocol}://${host}`;
}

function whatsappUrl(message = "") {
  return (
    "https://wa.me/" +
    SUPPORT_WHATSAPP +
    "?text=" +
    encodeURIComponent(message)
  );
}

/* =========================================================
   AUTH MIDDLEWARE
   ========================================================= */

function requireLogin(
  req,
  res,
  next
) {
  if (!req.session.user) {
    return res.status(401).json({
      success: false,
      message: "Please login first."
    });
  }

  next();
}

function requireAdmin(
  req,
  res,
  next
) {
  if (
    !req.session.user ||
    Number(req.session.user.is_admin) !== 1
  ) {
    return res.status(403).json({
      success: false,
      message: "Administrator access required."
    });
  }

  next();
}

/* =========================================================
   CURRENT USER
   ========================================================= */

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    is_admin: Number(user.is_admin)
  };
}

/* =========================================================
   ORDER ACCESS
   ========================================================= */

function getOrderForUser(
  orderNumber,
  user
) {
  const order = db
    .prepare(`
      SELECT
        o.*,

        p.name AS product_name,
        p.description AS product_description,
        p.image_url AS product_image,
        p.delivery_content AS product_delivery,

        u.name AS buyer_name,
        u.email AS buyer_email

      FROM orders o

      JOIN products p
        ON p.id = o.product_id

      JOIN users u
        ON u.id = o.user_id

      WHERE o.order_number = ?
    `)
    .get(orderNumber);

  if (!order) {
    return null;
  }

  if (
    Number(user.is_admin) !== 1 &&
    Number(order.user_id) !==
      Number(user.id)
  ) {
    return null;
  }

  return order;
}

function publicOrder(order) {
  const result = {
    id: order.id,
    order_number: order.order_number,

    product_id: order.product_id,
    product_name: order.product_name,
    product_description:
      order.product_description,
    product_image:
      order.product_image,

    amount_kes: Number(
      order.amount_kes
    ),

    amount_crypto:
      Number(order.amount_crypto || 0),

    payment_method:
      order.payment_method,

    payment_status:
      order.payment_status,

    delivery_method:
      order.delivery_method,

    delivery_target:
      order.delivery_target,

    phone:
      order.phone,

    delivery_status:
      order.delivery_status,

    delivery_notes:
      order.delivery_notes,

    created_at:
      order.created_at,

    paid_at:
      order.paid_at,

    delivered_at:
      order.delivered_at
  };

  /*
    Never expose the digital product content
    until payment AND delivery are confirmed.
  */

  if (
    order.payment_status === "paid" &&
    order.delivery_status === "delivered"
  ) {
    result.delivery_content =
      order.product_delivery || "";
  } else {
    result.delivery_content = "";
  }

  return result;
}

/* =========================================================
   AUTH API
   ========================================================= */

app.post(
  "/api/register",
  async (req, res) => {
    try {
      const name =
        cleanText(req.body.name);

      const email =
        cleanEmail(req.body.email);

      const password =
        String(req.body.password || "");

      if (
        name.length < 2 ||
        email.length < 5 ||
        password.length < 6
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter a valid name, email and password of at least 6 characters."
        });
      }

      if (!isValidEmail(email)) {
        return res.status(400).json({
          success: false,
          message:
            "Please enter a valid email address."
        });
      }

      const existing = db
        .prepare(
          `SELECT id
           FROM users
           WHERE email = ?`
        )
        .get(email);

      if (existing) {
        return res.status(409).json({
          success: false,
          message:
            "An account with this email already exists."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const result = db
        .prepare(`
          INSERT INTO users
            (name, email, password_hash)
          VALUES
            (?, ?, ?)
        `)
        .run(
          name,
          email,
          passwordHash
        );

      const user = db
        .prepare(
          `SELECT *
           FROM users
           WHERE id = ?`
        )
        .get(result.lastInsertRowid);

      req.session.user =
        publicUser(user);

      return res.json({
        success: true,
        message:
          "Account created successfully.",
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Registration failed."
      });
    }
  }
);

/* =========================================================
   LOGIN
   ========================================================= */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const email =
        cleanEmail(req.body.email);

      const password =
        String(req.body.password || "");

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Email and password are required."
        });
      }

      const user = db
        .prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `)
        .get(email);

      if (!user) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid email or password."
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid email or password."
        });
      }

      req.session.user =
        publicUser(user);

      return res.json({
        success: true,
        message: "Login successful.",
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Login failed."
      });
    }
  }
);

/* =========================================================
   ME
   ========================================================= */

app.get(
  "/api/me",
  (req, res) => {
    if (!req.session.user) {
      return res.json({
        success: true,
        authenticated: false,
        user: null
      });
    }

    return res.json({
      success: true,
      authenticated: true,
      user: req.session.user
    });
  }
);

/* =========================================================
   LOGOUT
   ========================================================= */

app.post(
  "/api/logout",
  (req, res) => {
    req.session.destroy(() => {
      res.clearCookie("connect.sid");

      return res.json({
        success: true,
        message: "Logged out."
      });
    });
  }
);

/* =========================================================
   PUBLIC PRODUCTS
   ========================================================= */

app.get(
  "/api/products",
  (req, res) => {
    try {
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

      return res.json({
        success: true,
        products
      });
    } catch (error) {
      console.error(
        "PRODUCT ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load products."
      });
    }
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
      const productId =
        Number(req.body.productId);

      const deliveryMethod =
        cleanText(
          req.body.deliveryMethod
        ).toLowerCase();

      const deliveryTarget =
        cleanText(
          req.body.deliveryTarget
        );

      const phone =
        String(
          req.body.phone || ""
        ).replace(/\D/g, "");

      const paymentMethod =
        cleanText(
          req.body.paymentMethod
        ).toLowerCase();

      if (
        !Number.isInteger(productId) ||
        productId <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid product."
        });
      }

      if (
        !["email", "whatsapp"].includes(
          deliveryMethod
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Choose email or WhatsApp delivery."
        });
      }

      if (
        !["paystack", "binance"].includes(
          paymentMethod
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Choose Paystack or Binance Pay."
        });
      }

      if (!deliveryTarget) {
        return res.status(400).json({
          success: false,
          message:
            "Delivery contact is required."
        });
      }

      if (
        deliveryMethod === "email" &&
        !isValidEmail(deliveryTarget)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter a valid delivery email."
        });
      }

      if (
        deliveryMethod === "whatsapp" &&
        !isValidWhatsApp(
          deliveryTarget
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter a valid WhatsApp number with country code."
        });
      }

      const product = db
        .prepare(`
          SELECT *
          FROM products
          WHERE id = ?
            AND active = 1
        `)
        .get(productId);

      if (!product) {
        return res.status(404).json({
          success: false,
          message:
            "Product is no longer available."
        });
      }

      if (
        paymentMethod === "binance" &&
        Number(product.binance_price || 0) <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Binance payment is not configured for this product."
        });
      }

      const orderNumber =
        makeOrderNumber();

      const amountKes =
        Number(product.price_kes);

      const amountCrypto =
        Number(
          product.binance_price || 0
        );

      db.prepare(`
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

        VALUES
        (
          ?, ?, ?, ?, ?, ?, 'pending',
          ?, ?, ?, 'pending'
        )
      `).run(
        orderNumber,
        req.session.user.id,
        product.id,
        amountKes,
        amountCrypto,
        paymentMethod,
        deliveryMethod,
        deliveryTarget,
        phone
      );

      const order =
        db.prepare(`
          SELECT *
          FROM orders
          WHERE order_number = ?
        `).get(orderNumber);

      return res.json({
        success: true,
        message:
          "Order created.",
        order: {
          order_number:
            order.order_number,
          amount_kes:
            order.amount_kes,
          amount_crypto:
            order.amount_crypto,
          payment_method:
            order.payment_method
        }
      });
    } catch (error) {
      console.error(
        "ORDER CREATE ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to create order."
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
    try {
      const orders = db
        .prepare(`
          SELECT
            o.*,

            p.name AS product_name,
            p.description AS product_description,
            p.image_url AS product_image,
            p.delivery_content AS product_delivery

          FROM orders o

          JOIN products p
            ON p.id = o.product_id

          WHERE o.user_id = ?

          ORDER BY o.id DESC
        `)
        .all(
          req.session.user.id
        );

      return res.json({
        success: true,
        orders:
          orders.map(
            publicOrder
          )
      });
    } catch (error) {
      console.error(
        "ORDERS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load orders."
      });
    }
  }
);

/* =========================================================
   SINGLE CUSTOMER ORDER
   ========================================================= */

app.get(
  "/api/orders/:orderNumber",
  requireLogin,
  (req, res) => {
    const order =
      getOrderForUser(
        req.params.orderNumber,
        req.session.user
      );

    if (!order) {
      return res.status(404).json({
        success: false,
        message:
          "Order not found."
      });
    }

    return res.json({
      success: true,
      order:
        publicOrder(order)
    });
  }
);

/* =========================================================
   PAYSTACK HELPERS
   ========================================================= */

function requirePaystack() {
  if (!PAYSTACK_SECRET_KEY) {
    throw new Error(
      "PAYSTACK_SECRET_KEY is not configured."
    );
  }
}

async function paystackRequest(
  method,
  endpoint,
  data
) {
  requirePaystack();

  const response =
    await axios({
      method,
      url:
        "https://api.paystack.co" +
        endpoint,

      data,

      headers: {
        Authorization:
          `Bearer ${PAYSTACK_SECRET_KEY}`,

        "Content-Type":
          "application/json"
      },

      timeout: 30000
    });

  return response.data;
}

/* =========================================================
   PAYSTACK INITIALIZE
   ========================================================= */

app.post(
  "/api/paystack/init",
  requireLogin,
  async (req, res) => {
    try {
      requirePaystack();

      const orderNumber =
        cleanText(
          req.body.orderNumber
        );

      const order =
        getOrderForUser(
          orderNumber,
          req.session.user
        );

      if (!order) {
        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      if (
        order.payment_method !==
        "paystack"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "This order is not a Paystack order."
        });
      }

      if (
        order.payment_status ===
        "paid"
      ) {
        return res.json({
          success: true,
          paid: true,
          message:
            "This order has already been paid."
        });
      }

      const reference =
        order.order_number;

      const baseUrl =
        getBaseUrl(req);

      const callbackUrl =
        `${baseUrl}/?payment=paystack&reference=${encodeURIComponent(
          reference
        )}`;

      const payload = {
        email:
          req.session.user.email,

        amount: String(
          Math.round(
            Number(order.amount_kes) *
              100
          )
        ),

        currency:
          PAYSTACK_CURRENCY,

        reference,

        callback_url:
          callbackUrl,

        metadata: JSON.stringify({
          order_number:
            order.order_number,

          user_id:
            req.session.user.id,

          product_id:
            order.product_id
        })
      };

      if (
        PAYSTACK_CHANNELS.length
      ) {
        payload.channels =
          PAYSTACK_CHANNELS;
      }

      const result =
        await paystackRequest(
          "POST",
          "/transaction/initialize",
          payload
        );

      if (
        !result ||
        !result.status ||
        !result.data
      ) {
        throw new Error(
          result?.message ||
            "Paystack initialization failed."
        );
      }

      db.prepare(`
        UPDATE orders

        SET
          paystack_reference = ?

        WHERE order_number = ?
      `).run(
        result.data.reference ||
          reference,

        order.order_number
      );

      return res.json({
        success: true,

        authorization_url:
          result.data
            .authorization_url,

        access_code:
          result.data
            .access_code,

        reference:
          result.data.reference ||
          reference
      });
    } catch (error) {
      console.error(
        "PAYSTACK INIT ERROR:",
        error.response?.data ||
          error.message
      );

      return res.status(500).json({
        success: false,
        message:
          error.response?.data?.message ||
          error.message ||
          "Paystack initialization failed."
      });
    }
  }
);

/* =========================================================
   PAYSTACK VERIFY
   ========================================================= */

async function verifyPaystackPayment(
  reference
) {
  const result =
    await paystackRequest(
      "GET",
      `/transaction/verify/${encodeURIComponent(
        reference
      )}`
    );

  if (
    !result ||
    !result.status ||
    !result.data
  ) {
    return {
      paid: false,
      data: null
    };
  }

  const data =
    result.data;

  const order =
    db.prepare(`
      SELECT *
      FROM orders
      WHERE
        order_number = ?
        OR paystack_reference = ?
    `).get(
      reference,
      reference
    );

  if (!order) {
    return {
      paid: false,
      data
    };
  }

  const expectedAmount =
    Math.round(
      Number(order.amount_kes) *
        100
    );

  const receivedAmount =
    Number(data.amount);

  const currency =
    String(
      data.currency || ""
    ).toUpperCase();

  const successful =
    String(data.status)
      .toLowerCase() ===
      "success";

  const amountMatches =
    receivedAmount ===
    expectedAmount;

  const currencyMatches =
    currency ===
    PAYSTACK_CURRENCY;

  if (
    successful &&
    amountMatches &&
    currencyMatches
  ) {
    db.prepare(`
      UPDATE orders

      SET
        payment_status = 'paid',
        paystack_reference = ?,
        paystack_transaction_id = ?,
        paystack_receipt = ?,
        paid_at = COALESCE(
          paid_at,
          CURRENT_TIMESTAMP
        )

      WHERE id = ?
    `).run(
      data.reference ||
        reference,

      String(
        data.id || ""
      ),

      String(
        data.receipt_number ||
          ""
      ),

      order.id
    );

    return {
      paid: true,
      data
    };
  }

  return {
    paid: false,
    data
  };
}

app.get(
  "/api/paystack/verify/:reference",
  requireLogin,
  async (req, res) => {
    try {
      const reference =
        cleanText(
          req.params.reference
        );

      const order =
        getOrderForUser(
          reference,
          req.session.user
        );

      if (!order) {
        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      const result =
        await verifyPaystackPayment(
          reference
        );

      const updated =
        db.prepare(`
          SELECT *

          FROM orders

          WHERE id = ?
        `).get(order.id);

      return res.json({
        success: true,

        paid:
          result.paid,

        order:
          publicOrder({
            ...updated,

            product_name:
              order.product_name,

            product_description:
              order.product_description,

            product_image:
              order.product_image,

            product_delivery:
              order.product_delivery
          })
      });
    } catch (error) {
      console.error(
        "PAYSTACK VERIFY ERROR:",
        error.response?.data ||
          error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to verify Paystack payment."
      });
    }
  }
);

/* =========================================================
   PAYSTACK WEBHOOK
   ========================================================= */

function safeSignatureCompare(
  received,
  calculated
) {
  if (!received) {
    return false;
  }

  const receivedBuffer =
    Buffer.from(
      String(received),
      "utf8"
    );

  const calculatedBuffer =
    Buffer.from(
      String(calculated),
      "utf8"
    );

  if (
    receivedBuffer.length !==
    calculatedBuffer.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    receivedBuffer,
    calculatedBuffer
  );
}

app.post(
  "/api/paystack/webhook",
  async (req, res) => {
    try {
      if (!PAYSTACK_SECRET_KEY) {
        return res.sendStatus(200);
      }

      const rawBody =
        req.rawBody ||
        Buffer.from(
          JSON.stringify(
            req.body || {}
          )
        );

      const receivedSignature =
        req.headers[
          "x-paystack-signature"
        ];

      const calculatedSignature =
        crypto
          .createHmac(
            "sha512",
            PAYSTACK_SECRET_KEY
          )
          .update(rawBody)
          .digest("hex");

      if (
        !safeSignatureCompare(
          receivedSignature,
          calculatedSignature
        )
      ) {
        return res.sendStatus(401);
      }

      const event =
        req.body || {};

      if (
        event.event ===
        "charge.success"
      ) {
        const reference =
          event.data?.reference;

        if (reference) {
          try {
            await verifyPaystackPayment(
              reference
            );
          } catch (error) {
            console.error(
              "PAYSTACK WEBHOOK VERIFY:",
              error.message
            );
          }
        }
      }

      return res.sendStatus(200);
    } catch (error) {
      console.error(
        "PAYSTACK WEBHOOK ERROR:",
        error.message
      );

      return res.sendStatus(200);
    }
  }
);

/* =========================================================
   BINANCE PAY HELPERS
   ========================================================= */

function requireBinance() {
  if (
    !BINANCE_API_KEY ||
    !BINANCE_SECRET_KEY
  ) {
    throw new Error(
      "BINANCE_PAY_API_KEY and BINANCE_PAY_SECRET_KEY are not configured."
    );
  }
}

function createBinanceHeaders(
  bodyString
) {
  requireBinance();

  const timestamp =
    Date.now().toString();

  const nonce =
    crypto
      .randomBytes(16)
      .toString("hex");

  const payload =
    timestamp +
    "\n" +
    nonce +
    "\n" +
    bodyString +
    "\n";

  const signature =
    crypto
      .createHmac(
        "sha512",
        BINANCE_SECRET_KEY
      )
      .update(payload)
      .digest("hex")
      .toUpperCase();

  return {
    "Content-Type":
      "application/json",

    "BinancePay-Timestamp":
      timestamp,

    "BinancePay-Nonce":
      nonce,

    "BinancePay-Certificate-SN":
      BINANCE_API_KEY,

    "BinancePay-Signature":
      signature
  };
}

async function binanceRequest(
  endpoint,
  payload
) {
  requireBinance();

  const bodyString =
    JSON.stringify(payload);

  const headers =
    createBinanceHeaders(
      bodyString
    );

  const response =
    await axios.post(
      BINANCE_BASE_URL +
        endpoint,

      bodyString,

      {
        headers,
        timeout: 30000
      }
    );

  return response.data;
}

/* =========================================================
   BINANCE CREATE ORDER
   ========================================================= */

app.post(
  "/api/binance/create",
  requireLogin,
  async (req, res) => {
    try {
      requireBinance();

      const orderNumber =
        cleanText(
          req.body.orderNumber
        );

      const order =
        getOrderForUser(
          orderNumber,
          req.session.user
        );

      if (!order) {
        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      if (
        order.payment_method !==
        "binance"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "This order is not a Binance order."
        });
      }

      if (
        order.payment_status ===
        "paid"
      ) {
        return res.json({
          success: true,
          paid: true,
          message:
            "This order is already paid."
        });
      }

      const merchantTradeNo =
        order.binance_merchant_trade_no ||
        makeBinanceTradeNo();

      const amount =
        Number(
          order.amount_crypto
        );

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid Binance amount."
        });
      }

      const baseUrl =
        getBaseUrl(req);

      const returnUrl =
        `${baseUrl}/?payment=binance&order=${encodeURIComponent(
          order.order_number
        )}`;

      const cancelUrl =
        `${baseUrl}/?payment=binance_cancelled&order=${encodeURIComponent(
          order.order_number
        )}`;

      /*
        Binance Pay order structure.
        The merchant API credentials remain
        server-side only.
      */

      const payload = {
        env: {
          terminalType: "WEB"
        },

        merchantTradeNo:
          merchantTradeNo,

        orderAmount:
          Number(amount.toFixed(8)),

        currency:
          BINANCE_CURRENCY,

        goods: {
          goodsType: "01",

          goodsCategory: "0000",

          referenceGoodsId:
            String(
              order.product_id
            ),

          goodsName:
            String(
              order.product_name
            ).slice(0, 256),

          goodsDetail:
            String(
              order.product_description ||
                ""
            ).slice(0, 256),

          goodsUnitAmount: {
            currency:
              BINANCE_CURRENCY,

            amount:
              Number(
                amount.toFixed(8)
              )
          }
        },

        returnUrl,

        cancelUrl
      };

      const result =
        await binanceRequest(
          "/binancepay/openapi/v2/order",
          payload
        );

      if (
        !result ||
        result.status !==
          "SUCCESS" ||
        !result.data
      ) {
        throw new Error(
          result?.errorMessage ||
            result?.message ||
            "Binance Pay order creation failed."
        );
      }

      db.prepare(`
        UPDATE orders

        SET
          binance_merchant_trade_no = ?,
          binance_prepay_id = ?

        WHERE id = ?
      `).run(
        merchantTradeNo,

        String(
          result.data.prepayId ||
            ""
        ),

        order.id
      );

      return res.json({
        success: true,

        merchantTradeNo,

        prepayId:
          result.data.prepayId ||
          "",

        checkoutUrl:
          result.data.checkoutUrl ||
          "",

        qrCodeLink:
          result.data.qrcodeLink ||
          "",

        qrContent:
          result.data.qrContent ||
          "",

        deeplink:
          result.data.deeplink ||
          ""
      });
    } catch (error) {
      console.error(
        "BINANCE CREATE ERROR:",
        error.response?.data ||
          error.message
      );

      return res.status(500).json({
        success: false,
        message:
          error.response?.data?.errorMessage ||
          error.response?.data?.message ||
          error.message ||
          "Binance Pay order creation failed."
      });
    }
  }
);

/* =========================================================
   BINANCE QUERY
   ========================================================= */

async function queryBinanceOrder(
  order
) {
  const payload = {
    merchantTradeNo:
      order.binance_merchant_trade_no ||
      null,

    prepayId:
      order.binance_prepay_id ||
      null
  };

  const result =
    await binanceRequest(
      "/binancepay/openapi/order/query",
      payload
    );

  return result;
}

function extractBinanceStatus(
  result
) {
  return String(
    result?.data?.status ||
      result?.data?.orderStatus ||
      ""
  ).toUpperCase();
}

/* =========================================================
   BINANCE CHECK
   ========================================================= */

app.get(
  "/api/binance/check/:orderNumber",
  requireLogin,
  async (req, res) => {
    try {
      requireBinance();

      const order =
        getOrderForUser(
          req.params.orderNumber,
          req.session.user
        );

      if (!order) {
        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      if (
        order.payment_method !==
        "binance"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "This is not a Binance order."
        });
      }

      const result =
        await queryBinanceOrder(
          order
        );

      const status =
        extractBinanceStatus(
          result
        );

      const paid =
        status === "PAID";

      if (paid) {
        db.prepare(`
          UPDATE orders

          SET
            payment_status = 'paid',
            paid_at = COALESCE(
              paid_at,
              CURRENT_TIMESTAMP
            ),
            binance_transaction_id = ?

          WHERE id = ?
        `).run(
          String(
            result.data?.transactionId ||
              result.data?.transactId ||
              ""
          ),

          order.id
        );
      }

      const updated =
        db.prepare(`
          SELECT *

          FROM orders

          WHERE id = ?
        `).get(order.id);

      return res.json({
        success: true,

        paid,

        status,

        order:
          publicOrder({
            ...updated,

            product_name:
              order.product_name,

            product_description:
              order.product_description,

            product_image:
              order.product_image,

            product_delivery:
              order.product_delivery
          })
      });
    } catch (error) {
      console.error(
        "BINANCE CHECK ERROR:",
        error.response?.data ||
          error.message
      );

      return res.status(500).json({
        success: false,
        message:
          error.response?.data?.errorMessage ||
          error.response?.data?.message ||
          error.message ||
          "Unable to check Binance payment."
      });
    }
  }
);

/* =========================================================
   BINANCE WEBHOOK
   ========================================================= */

function verifyBinanceIncomingSignature(
  req
) {
  if (!BINANCE_SECRET_KEY) {
    return false;
  }

  const timestamp =
    req.headers[
      "binancepay-timestamp"
    ];

  const nonce =
    req.headers[
      "binancepay-nonce"
    ];

  const receivedSignature =
    req.headers[
      "binancepay-signature"
    ];

  if (
    !timestamp ||
    !nonce ||
    !receivedSignature
  ) {
    return false;
  }

  const rawBody =
    req.rawBody ||
    Buffer.from(
      JSON.stringify(
        req.body || {}
      )
    );

  const payload =
    timestamp +
    "\n" +
    nonce +
    "\n" +
    rawBody.toString("utf8") +
    "\n";

  const calculated =
    crypto
      .createHmac(
        "sha512",
        BINANCE_SECRET_KEY
      )
      .update(payload)
      .digest("hex")
      .toUpperCase();

  return safeSignatureCompare(
    receivedSignature,
    calculated
  );
}

app.post(
  "/api/binance/webhook",
  async (req, res) => {
    try {
      if (!BINANCE_SECRET_KEY) {
        return res.json({
          returnCode: "SUCCESS",
          returnMessage: "OK"
        });
      }

      /*
        Reject unsigned notifications.
      */

      if (
        !verifyBinanceIncomingSignature(
          req
        )
      ) {
        return res.status(401).json({
          returnCode:
            "FAIL",
          returnMessage:
            "Invalid signature"
        });
      }

      let notification =
        req.body || {};

      /*
        Binance can provide nested data
        as a JSON string.
      */

      let data =
        notification.data;

      if (
        typeof data ===
        "string"
      ) {
        try {
          data = JSON.parse(data);
        } catch {
          data = {};
        }
      }

      const merchantTradeNo =
        data?.merchantTradeNo ||
        notification?.merchantTradeNo;

      if (merchantTradeNo) {
        const order =
          db.prepare(`
            SELECT *

            FROM orders

            WHERE
              binance_merchant_trade_no = ?
          `).get(
            merchantTradeNo
          );

        /*
          Confirm payment with Binance
          instead of trusting only the webhook.
        */

        if (
          order &&
          order.payment_status !==
            "paid"
        ) {
          try {
            const result =
              await queryBinanceOrder(
                order
              );

            const status =
              extractBinanceStatus(
                result
              );

            if (
              status === "PAID"
            ) {
              db.prepare(`
                UPDATE orders

                SET
                  payment_status = 'paid',
                  paid_at = COALESCE(
                    paid_at,
                    CURRENT_TIMESTAMP
                  ),
                  binance_transaction_id = ?

                WHERE id = ?
              `).run(
                String(
                  result.data
                    ?.transactionId ||
                    result.data
                      ?.transactId ||
                    ""
                ),

                order.id
              );
            }
          } catch (error) {
            console.error(
              "BINANCE WEBHOOK QUERY ERROR:",
              error.message
            );
          }
        }
      }

      return res.json({
        returnCode: "SUCCESS",
        returnMessage: "OK"
      });
    } catch (error) {
      console.error(
        "BINANCE WEBHOOK ERROR:",
        error.message
      );

      return res.json({
        returnCode: "SUCCESS",
        returnMessage: "OK"
      });
    }
  }
);

/* =========================================================
   ADMIN USERS
   ========================================================= */

app.get(
  "/api/admin/users",
  requireAdmin,
  (req, res) => {
    try {
      const users = db
        .prepare(`
          SELECT
            u.id,
            u.name,
            u.email,
            u.is_admin,
            u.created_at,

            COUNT(o.id)
              AS order_count,

            COALESCE(
              SUM(
                CASE
                  WHEN o.payment_status =
                    'paid'
                  THEN o.amount_kes
                  ELSE 0
                END
              ),
              0
            ) AS total_paid

          FROM users u

          LEFT JOIN orders o
            ON o.user_id = u.id

          GROUP BY u.id

          ORDER BY u.id DESC
        `)
        .all();

      return res.json({
        success: true,
        users
      });
    } catch (error) {
      console.error(
        "ADMIN USERS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load users."
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
    try {
      const orders = db
        .prepare(`
          SELECT
            o.*,

            p.name AS product_name,
            p.image_url AS product_image,
            p.delivery_content AS product_delivery,

            u.name AS buyer_name,
            u.email AS buyer_email

          FROM orders o

          JOIN products p
            ON p.id = o.product_id

          JOIN users u
            ON u.id = o.user_id

          ORDER BY o.id DESC
        `)
        .all();

      return res.json({
        success: true,
        orders
      });
    } catch (error) {
      console.error(
        "ADMIN ORDERS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load orders."
      });
    }
  }
);

/* =========================================================
   ADMIN PRODUCTS
   ========================================================= */

app.get(
  "/api/admin/products",
  requireAdmin,
  (req, res) => {
    const products =
      db.prepare(`
        SELECT *
        FROM products
        ORDER BY id DESC
      `).all();

    return res.json({
      success: true,
      products
    });
  }
);

/* =========================================================
   MULTER
   ========================================================= */

const storage =
  multer.diskStorage({
    destination:
      function (
        req,
        file,
        cb
      ) {
        cb(
          null,
          UPLOAD_DIR
        );
      },

    filename:
      function (
        req,
        file,
        cb
      ) {
        const extension =
          path
            .extname(
              file.originalname
            )
            .toLowerCase();

        const filename =
          "product-" +
          Date.now() +
          "-" +
          crypto
            .randomBytes(4)
            .toString("hex") +
          extension;

        cb(
          null,
          filename
        );
      }
  });

const upload =
  multer({
    storage,

    limits: {
      fileSize:
        5 * 1024 * 1024
    },

    fileFilter:
      function (
        req,
        file,
        cb
      ) {
        const allowed =
          [
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/gif"
          ];

        if (
          allowed.includes(
            file.mimetype
          )
        ) {
          cb(
            null,
            true
          );
        } else {
          cb(
            new Error(
              "Only JPG, PNG, WEBP and GIF images are allowed."
            )
          );
        }
      }
  });

/* =========================================================
   ADMIN ADD PRODUCT
   ========================================================= */

app.post(
  "/api/admin/products",
  requireAdmin,
  upload.single("image"),
  (req, res) => {
    try {
      const name =
        cleanText(
          req.body.name
        );

      const description =
        cleanText(
          req.body.description
        );

      const priceKes =
        Number(
          req.body.priceKes
        );

      const binancePrice =
        Number(
          req.body.binancePrice ||
            0
        );

      const deliveryContent =
        String(
          req.body.deliveryContent ||
            ""
        );

      if (!name) {
        return res.status(400).json({
          success: false,
          message:
            "Product name is required."
        });
      }

      if (
        !Number.isFinite(
          priceKes
        ) ||
        priceKes <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter a valid KES price."
        });
      }

      if (
        binancePrice < 0 ||
        !Number.isFinite(
          binancePrice
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid Binance price."
        });
      }

      let imageUrl = "";

      if (req.file) {
        imageUrl =
          "/uploads/products/" +
          req.file.filename;
      }

      const result =
        db.prepare(`
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

          VALUES
          (?, ?, ?, ?, ?, ?, 1)
        `).run(
          name,
          description,
          priceKes,
          binancePrice,
          deliveryContent,
          imageUrl
        );

      const product =
        db.prepare(`
          SELECT *
          FROM products
          WHERE id = ?
        `).get(
          result.lastInsertRowid
        );

      return res.json({
        success: true,
        message:
          "Product added successfully.",
        product
      });
    } catch (error) {
      console.error(
        "ADMIN PRODUCT ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          error.message ||
          "Unable to add product."
      });
    }
  }
);

/* =========================================================
   ADMIN TOGGLE PRODUCT
   ========================================================= */

app.post(
  "/api/admin/products/:id/toggle",
  requireAdmin,
  (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const product =
        db.prepare(`
          SELECT *
          FROM products
          WHERE id = ?
        `).get(id);

      if (!product) {
        return res.status(404).json({
          success: false,
          message:
            "Product not found."
        });
      }

      const newStatus =
        Number(product.active) ===
        1
          ? 0
          : 1;

      db.prepare(`
        UPDATE products
        SET active = ?
        WHERE id = ?
      `).run(
        newStatus,
        id
      );

      return res.json({
        success: true,
        active: newStatus
      });
    } catch (error) {
      console.error(
        "PRODUCT TOGGLE ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to update product."
      });
    }
  }
);

/* =========================================================
   ADMIN DELETE PRODUCT
   ========================================================= */

app.delete(
  "/api/admin/products/:id",
  requireAdmin,
  (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const product =
        db.prepare(`
          SELECT *
          FROM products
          WHERE id = ?
        `).get(id);

      if (!product) {
        return res.status(404).json({
          success: false,
          message:
            "Product not found."
        });
      }

      const existingOrders =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM orders
          WHERE product_id = ?
        `).get(id);

      if (
        Number(
          existingOrders.count
        ) > 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "This product has orders. Disable it instead of deleting it."
        });
      }

      db.prepare(`
        DELETE FROM products
        WHERE id = ?
      `).run(id);

      if (
        product.image_url
      ) {
        const imagePath =
          path.join(
            PUBLIC_DIR,
            product.image_url
              .replace(
                /^\//,
                ""
              )
          );

        if (
          fs.existsSync(
            imagePath
          )
        ) {
          try {
            fs.unlinkSync(
              imagePath
            );
          } catch {}
        }
      }

      return res.json({
        success: true,
        message:
          "Product deleted."
      });
    } catch (error) {
      console.error(
        "PRODUCT DELETE ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to delete product."
      });
    }
  }
);

/* =========================================================
   ADMIN DELIVERY UPDATE
   ========================================================= */

app.post(
  "/api/admin/orders/:orderNumber/delivery",
  requireAdmin,
  (req, res) => {
    try {
      const orderNumber =
        cleanText(
          req.params.orderNumber
        );

      const status =
        cleanText(
          req.body.status
        ).toLowerCase();

      const notes =
        cleanText(
          req.body.notes
        );

      const allowedStatuses =
        [
          "pending",
          "processing",
          "delivered"
        ];

      if (
        !allowedStatuses.includes(
          status
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid delivery status."
        });
      }

      const order =
        db.prepare(`
          SELECT *
          FROM orders
          WHERE order_number = ?
        `).get(orderNumber);

      if (!order) {
        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      if (
        status === "delivered" &&
        order.payment_status !==
          "paid"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "You cannot mark an unpaid order as delivered."
        });
      }

      db.prepare(`
        UPDATE orders

        SET
          delivery_status = ?,
          delivery_notes = ?,
          delivered_at =
            CASE
              WHEN ? = 'delivered'
              THEN COALESCE(
                delivered_at,
                CURRENT_TIMESTAMP
              )
              ELSE delivered_at
            END

        WHERE order_number = ?
      `).run(
        status,
        notes,
        status,
        orderNumber
      );

      return res.json({
        success: true,
        message:
          "Delivery status updated."
      });
    } catch (error) {
      console.error(
        "DELIVERY UPDATE ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to update delivery."
      });
    }
  }
);

/* =========================================================
   ADMIN PAYMENT RECHECK
   ========================================================= */

app.post(
  "/api/admin/orders/:orderNumber/check-payment",
  requireAdmin,
  async (req, res) => {
    try {
      const orderNumber =
        cleanText(
          req.params.orderNumber
        );

      const order =
        db.prepare(`
          SELECT *
          FROM orders
          WHERE order_number = ?
        `).get(orderNumber);

      if (!order) {
        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      let result;

      if (
        order.payment_method ===
        "paystack"
      ) {
        result =
          await verifyPaystackPayment(
            order.paystack_reference ||
              order.order_number
          );
      } else if (
        order.payment_method ===
        "binance"
      ) {
        const binance =
          await queryBinanceOrder(
            order
          );

        if (
          extractBinanceStatus(
            binance
          ) === "PAID"
        ) {
          db.prepare(`
            UPDATE orders

            SET
              payment_status = 'paid',
              paid_at = COALESCE(
                paid_at,
                CURRENT_TIMESTAMP
              ),
              binance_transaction_id = ?

            WHERE id = ?
          `).run(
            String(
              binance.data
                ?.transactionId ||
                binance.data
                  ?.transactId ||
                ""
            ),

            order.id
          );
        }

        result = {
          paid:
            extractBinanceStatus(
              binance
            ) === "PAID"
        };
      } else {
        return res.status(400).json({
          success: false,
          message:
            "Unsupported payment method."
        });
      }

      return res.json({
        success: true,
        paid:
          Boolean(result.paid)
      });
    } catch (error) {
      console.error(
        "ADMIN PAYMENT CHECK ERROR:",
        error.response?.data ||
          error.message
      );

      return res.status(500).json({
        success: false,
        message:
          error.response?.data?.message ||
          error.message ||
          "Payment check failed."
      });
    }
  }
);

/* =========================================================
   SUPPORT INFORMATION
   ========================================================= */

app.get(
  "/api/support",
  (req, res) => {
    return res.json({
      success: true,

      whatsapp:
        SUPPORT_WHATSAPP,

      whatsapp_url:
        whatsappUrl(
          "Hello DARK WEB support, I need help with my order."
        )
    });
  }
);

/* =========================================================
   HEALTH CHECK
   ========================================================= */

app.get(
  "/api/health",
  (req, res) => {
    return res.json({
      success: true,

      app:
        "DARK WEB STORE",

      status:
        "online",

      payments: {
        paystack:
          Boolean(
            PAYSTACK_SECRET_KEY
          ),

        binance:
          Boolean(
            BINANCE_API_KEY &&
            BINANCE_SECRET_KEY
          )
      },

      admin:
        ADMIN_EMAIL,

      support:
        SUPPORT_WHATSAPP,

      time:
        new Date().toISOString()
    });
  }
);

/* =========================================================
   ERROR HANDLER
   ========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    if (
      error instanceof
      multer.MulterError
    ) {
      if (
        error.code ===
        "LIMIT_FILE_SIZE"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Image is too large. Maximum size is 5MB."
        });
      }

      return res.status(400).json({
        success: false,
        message:
          error.message
      });
    }

    return res.status(500).json({
      success: false,
      message:
        error.message ||
        "Internal server error."
    });
  }
);

/* =========================================================
   FRONTEND FALLBACK
   Express 5 syntax
   ========================================================= */

app.get(
  "*splat",
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "index.html"
      )
    );
  }
);

/* =========================================================
   START SERVER
   ========================================================= */

app.listen(
  PORT,
  () => {
    console.log(
      "======================================"
    );

    console.log(
      "DARK WEB STORE ONLINE"
    );

    console.log(
      "PORT:",
      PORT
    );

    console.log(
      "ADMIN:",
      ADMIN_EMAIL
    );

    console.log(
      "PAYSTACK:",
      PAYSTACK_SECRET_KEY
        ? "CONFIGURED"
        : "NOT CONFIGURED"
    );

    console.log(
      "BINANCE PAY:",
      BINANCE_API_KEY &&
        BINANCE_SECRET_KEY
        ? "CONFIGURED"
        : "NOT CONFIGURED"
    );

    console.log(
      "WHATSAPP:",
      SUPPORT_WHATSAPP
    );

    console.log(
      "======================================"
    );
  }
);
