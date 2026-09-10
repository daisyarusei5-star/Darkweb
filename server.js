"use strict";

/* =========================================================
   DARK WEB DIGITAL STORE
   Paystack + Binance Pay
   Express + SQLite
   Render Ready
   ========================================================= */

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const axios = require("axios");
const multer = require("multer");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

/* =========================================================
   CONFIG
   ========================================================= */

const app = express();

const PORT = Number(process.env.PORT || 3000);

const BASE_URL =
  String(process.env.BASE_URL || "").trim().replace(/\/+$/, "");

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
   EXPRESS
   ========================================================= */

app.use(
  express.json({
    limit: "2mb",
    verify: (req, res, buf) => {
      req.rawBody = Buffer.from(buf);
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
    secret:
      process.env.SESSION_SECRET ||
      "CHANGE_THIS_SESSION_SECRET_IN_RENDER",

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure:
        process.env.NODE_ENV === "production",
      maxAge:
        1000 * 60 * 60 * 24 * 7
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
   DATABASE
   ========================================================= */

const DB_PATH =
  process.env.DB_PATH ||
  path.join(__dirname, "darkweb.db");

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");

db.pragma("foreign_keys = ON");

/* =========================================================
   TABLES
   ========================================================= */

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_admin INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  price_kes REAL NOT NULL DEFAULT 0,
  binance_price REAL NOT NULL DEFAULT 0,
  delivery_content TEXT DEFAULT '',
  image_url TEXT DEFAULT '',
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  order_number TEXT NOT NULL UNIQUE,

  user_id INTEGER NOT NULL,

  product_id INTEGER NOT NULL,

  amount_kes REAL DEFAULT 0,

  amount_crypto REAL DEFAULT 0,

  payment_method TEXT DEFAULT '',

  payment_status TEXT DEFAULT 'pending',

  delivery_method TEXT DEFAULT '',

  delivery_target TEXT DEFAULT '',

  phone TEXT DEFAULT '',

  checkout_request_id TEXT DEFAULT '',

  merchant_request_id TEXT DEFAULT '',

  mpesa_receipt TEXT DEFAULT '',

  paystack_reference TEXT DEFAULT '',

  paystack_transaction_id TEXT DEFAULT '',

  paystack_receipt TEXT DEFAULT '',

  binance_merchant_trade_no TEXT DEFAULT '',

  binance_prepay_id TEXT DEFAULT '',

  binance_transaction_id TEXT DEFAULT '',

  binance_verified INTEGER DEFAULT 0,

  binance_txid TEXT DEFAULT '',

  delivery_status TEXT DEFAULT 'pending',

  delivery_notes TEXT DEFAULT '',

  created_at TEXT DEFAULT CURRENT_TIMESTAMP,

  paid_at TEXT DEFAULT '',

  delivered_at TEXT DEFAULT '',

  FOREIGN KEY(user_id)
    REFERENCES users(id),

  FOREIGN KEY(product_id)
    REFERENCES products(id)
);
`);

/* =========================================================
   DATABASE MIGRATION
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
    (item) =>
      item.name === column
  );

  if (!exists) {
    db.exec(
      `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
    );
  }
}

/* Orders */

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

addColumnIfMissing(
  "orders",
  "binance_verified",
  "INTEGER DEFAULT 0"
);

addColumnIfMissing(
  "orders",
  "binance_txid",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "orders",
  "delivery_status",
  "TEXT DEFAULT 'pending'"
);

addColumnIfMissing(
  "orders",
  "delivery_notes",
  "TEXT DEFAULT ''"
);

/* Products */

addColumnIfMissing(
  "products",
  "binance_price",
  "REAL DEFAULT 0"
);

addColumnIfMissing(
  "products",
  "delivery_content",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "products",
  "image_url",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "products",
  "active",
  "INTEGER DEFAULT 1"
);

/* =========================================================
   ADMIN
   ========================================================= */

const adminEmail = String(
  process.env.ADMIN_EMAIL ||
    "admin@example.com"
)
  .trim()
  .toLowerCase();

const adminPassword = String(
  process.env.ADMIN_PASSWORD ||
    "ChangeMe123!"
);

if (adminPassword.length < 6) {
  throw new Error(
    "ADMIN_PASSWORD must contain at least 6 characters."
  );
}

const adminPasswordHash =
  bcrypt.hashSync(
    adminPassword,
    12
  );

const existingAdmin = db
  .prepare(
    `
    SELECT *
    FROM users
    WHERE email = ?
    `
  )
  .get(adminEmail);

if (!existingAdmin) {
  db.prepare(
    `
    INSERT INTO users
    (
      name,
      email,
      password_hash,
      is_admin
    )
    VALUES (?, ?, ?, 1)
    `
  ).run(
    "Administrator",
    adminEmail,
    adminPasswordHash
  );

  console.log(
    "ADMIN CREATED:",
    adminEmail
  );
} else {
  db.prepare(
    `
    UPDATE users
    SET
      password_hash = ?,
      is_admin = 1,
      name = 'Administrator'
    WHERE email = ?
    `
  ).run(
    adminPasswordHash,
    adminEmail
  );

  console.log(
    "ADMIN UPDATED:",
    adminEmail
  );
}

/* =========================================================
   HELPERS
   ========================================================= */

function cleanEmail(value) {
  return String(
    value || ""
  )
    .trim()
    .toLowerCase();
}

function cleanText(value) {
  return String(
    value || ""
  ).trim();
}

function money(value) {
  return Number(
    Number(value || 0).toFixed(2)
  );
}

function makeOrderNumber() {
  return (
    "DW" +
    Date.now().toString(36).toUpperCase() +
    crypto
      .randomBytes(4)
      .toString("hex")
      .toUpperCase()
  );
}

function makeBinanceTradeNo() {
  /*
    Binance merchantTradeNo:
    maximum 32 characters
    letters/numbers only
  */

  return (
    "DW" +
    Date.now().toString(36).toUpperCase() +
    crypto
      .randomBytes(5)
      .toString("hex")
      .toUpperCase()
  ).slice(0, 32);
}

function getBaseUrl(req) {
  if (BASE_URL) {
    return BASE_URL;
  }

  const protocol =
    req.headers["x-forwarded-proto"] ||
    req.protocol ||
    "http";

  const host =
    req.headers["x-forwarded-host"] ||
    req.get("host");

  return `${protocol}://${host}`;
}

function safeUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    is_admin: Number(
      user.is_admin
    )
  };
}

function requireLogin(
  req,
  res,
  next
) {
  if (!req.session.userId) {
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
  if (!req.session.userId) {
    return res.status(401).json({
      success: false,
      message: "Login required."
    });
  }

  const user = db
    .prepare(
      `
      SELECT *
      FROM users
      WHERE id = ?
      `
    )
    .get(
      req.session.userId
    );

  if (
    !user ||
    Number(user.is_admin) !== 1
  ) {
    return res.status(403).json({
      success: false,
      message: "Admin access required."
    });
  }

  next();
}

function getOrderForUser(
  orderNumber,
  userId
) {
  return db
    .prepare(
      `
      SELECT
        o.*,
        p.name AS product_name,
        p.description AS product_description,
        p.image_url AS product_image,
        p.delivery_content
      FROM orders o
      JOIN products p
        ON p.id = o.product_id
      WHERE
        o.order_number = ?
        AND o.user_id = ?
      `
    )
    .get(
      orderNumber,
      userId
    );
}

/* =========================================================
   AUTH
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
        String(
          req.body.password || ""
        );

      if (
        name.length < 2 ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Name, email and password are required."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Password must contain at least 6 characters."
        });
      }

      const existing = db
        .prepare(
          `
          SELECT id
          FROM users
          WHERE email = ?
          `
        )
        .get(email);

      if (existing) {
        return res.status(409).json({
          success: false,
          message:
            "Email already registered."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const result = db
        .prepare(
          `
          INSERT INTO users
          (
            name,
            email,
            password_hash,
            is_admin
          )
          VALUES (?, ?, ?, 0)
          `
        )
        .run(
          name,
          email,
          passwordHash
        );

      const user = db
        .prepare(
          `
          SELECT *
          FROM users
          WHERE id = ?
          `
        )
        .get(
          result.lastInsertRowid
        );

      req.session.userId =
        user.id;

      return res.json({
        success: true,
        user: safeUser(user)
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

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const email =
        cleanEmail(req.body.email);

      const password =
        String(
          req.body.password || ""
        );

      const user = db
        .prepare(
          `
          SELECT *
          FROM users
          WHERE email = ?
          `
        )
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

      req.session.userId =
        user.id;

      return res.json({
        success: true,
        user: safeUser(user)
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

app.get(
  "/api/me",
  (req, res) => {
    if (!req.session.userId) {
      return res.json({
        success: true,
        user: null
      });
    }

    const user = db
      .prepare(
        `
        SELECT *
        FROM users
        WHERE id = ?
        `
      )
      .get(
        req.session.userId
      );

    return res.json({
      success: true,
      user: safeUser(user)
    });
  }
);

app.post(
  "/api/logout",
  (req, res) => {
    req.session.destroy(() => {
      res.json({
        success: true
      });
    });
  }
);

/* =========================================================
   PRODUCTS - PUBLIC
   ========================================================= */

app.get(
  "/api/products",
  (req, res) => {
    try {
      const products = db
        .prepare(
          `
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
          `
        )
        .all();

      res.json({
        success: true,
        products
      });
    } catch (error) {
      console.error(
        "PRODUCTS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load products."
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
    const products = db
      .prepare(
        `
        SELECT *
        FROM products
        ORDER BY id DESC
        `
      )
      .all();

    res.json({
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
          path.extname(
            file.originalname
          ).toLowerCase();

        const filename =
          Date.now() +
          "-" +
          crypto
            .randomBytes(5)
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
        const allowed = [
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
          cb(null, true);
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
   ADD PRODUCT
   ========================================================= */

app.post(
  "/api/admin/products",
  requireAdmin,
  upload.single("image"),
  (req, res) => {
    try {
      const name =
        cleanText(req.body.name);

      const description =
        cleanText(
          req.body.description
        );

      const priceKes =
        money(
          req.body.price_kes
        );

      const binancePrice =
        money(
          req.body.binance_price
        );

      const deliveryContent =
        String(
          req.body.delivery_content ||
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
        priceKes <= 0 &&
        binancePrice <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Set a valid KSh or Binance price."
        });
      }

      let imageUrl = "";

      if (req.file) {
        imageUrl =
          "/uploads/products/" +
          req.file.filename;
      }

      const result = db
        .prepare(
          `
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
          `
        )
        .run(
          name,
          description,
          priceKes,
          binancePrice,
          deliveryContent,
          imageUrl
        );

      const product = db
        .prepare(
          `
          SELECT *
          FROM products
          WHERE id = ?
          `
        )
        .get(
          result.lastInsertRowid
        );

      res.json({
        success: true,
        message:
          "Product added successfully.",
        product
      });
    } catch (error) {
      console.error(
        "ADD PRODUCT ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message ||
          "Unable to add product."
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
    const productId =
      Number(req.params.id);

    const product = db
      .prepare(
        `
        SELECT *
        FROM products
        WHERE id = ?
        `
      )
      .get(productId);

    if (!product) {
      return res.status(404).json({
        success: false,
        message:
          "Product not found."
      });
    }

    db.prepare(
      `
      UPDATE products
      SET active = ?
      WHERE id = ?
      `
    ).run(
      Number(product.active)
        ? 0
        : 1,
      productId
    );

    res.json({
      success: true
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
    const productId =
      Number(req.params.id);

    const product = db
      .prepare(
        `
        SELECT *
        FROM products
        WHERE id = ?
        `
      )
      .get(productId);

    if (!product) {
      return res.status(404).json({
        success: false,
        message:
          "Product not found."
      });
    }

    db.prepare(
      `
      DELETE FROM products
      WHERE id = ?
      `
    ).run(productId);

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
      const productId =
        Number(
          req.body.product_id
        );

      const deliveryMethod =
        cleanText(
          req.body.delivery_method
        );

      const deliveryTarget =
        cleanText(
          req.body.delivery_target
        );

      const phone =
        cleanText(
          req.body.phone
        );

      const paymentMethod =
        cleanText(
          req.body.payment_method
        ).toLowerCase();

      const product = db
        .prepare(
          `
          SELECT *
          FROM products
          WHERE id = ?
          AND active = 1
          `
        )
        .get(productId);

      if (!product) {
        return res.status(404).json({
          success: false,
          message:
            "Product is no longer available."
        });
      }

      if (
        !["email", "whatsapp"]
          .includes(
            deliveryMethod
          )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Choose email or WhatsApp delivery."
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
        !["paystack", "binance"]
          .includes(
            paymentMethod
          )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Choose Paystack or Binance."
        });
      }

      let amountKes =
        Number(product.price_kes);

      let amountCrypto =
        Number(
          product.binance_price
        );

      if (
        paymentMethod ===
          "paystack" &&
        amountKes <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Paystack price is not configured for this product."
        });
      }

      if (
        paymentMethod ===
          "binance" &&
        amountCrypto <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Binance price is not configured for this product."
        });
      }

      const orderNumber =
        makeOrderNumber();

      const result = db
        .prepare(
          `
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
          VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, 'pending')
          `
        )
        .run(
          orderNumber,
          req.session.userId,
          product.id,
          amountKes,
          amountCrypto,
          paymentMethod,
          deliveryMethod,
          deliveryTarget,
          phone
        );

      const order = db
        .prepare(
          `
          SELECT *
          FROM orders
          WHERE id = ?
          `
        )
        .get(
          result.lastInsertRowid
        );

      res.json({
        success: true,
        order
      });
    } catch (error) {
      console.error(
        "CREATE ORDER ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to create order."
      });
    }
  }
);

/* =========================================================
   USER ORDERS
   ========================================================= */

app.get(
  "/api/orders",
  requireLogin,
  (req, res) => {
    try {
      const orders = db
        .prepare(
          `
          SELECT
            o.id,
            o.order_number,
            o.amount_kes,
            o.amount_crypto,
            o.payment_method,
            o.payment_status,
            o.delivery_method,
            o.delivery_target,
            o.phone,
            o.paystack_reference,
            o.binance_merchant_trade_no,
            o.binance_prepay_id,
            o.binance_transaction_id,
            o.delivery_status,
            o.delivery_notes,
            o.created_at,
            o.paid_at,
            o.delivered_at,
            p.name AS product_name,
            p.image_url AS product_image
          FROM orders o
          JOIN products p
            ON p.id = o.product_id
          WHERE o.user_id = ?
          ORDER BY o.id DESC
          `
        )
        .all(
          req.session.userId
        );

      res.json({
        success: true,
        orders
      });
    } catch (error) {
      console.error(
        "USER ORDERS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load orders."
      });
    }
  }
);

/* =========================================================
   SINGLE USER ORDER
   ========================================================= */

app.get(
  "/api/orders/:orderNumber",
  requireLogin,
  (req, res) => {
    const order =
      getOrderForUser(
        req.params.orderNumber,
        req.session.userId
      );

    if (!order) {
      return res.status(404).json({
        success: false,
        message:
          "Order not found."
      });
    }

    const response = {
      ...order
    };

    /*
      Do not expose delivery content
      until the order is actually paid
      and marked delivered.
    */

    if (
      order.payment_status !==
        "paid" ||
      order.delivery_status !==
        "delivered"
    ) {
      delete response.delivery_content;
    }

    res.json({
      success: true,
      order: response
    });
  }
);

/* =========================================================
   PAYSTACK
   ========================================================= */

const PAYSTACK_URL =
  "https://api.paystack.co";

function paystackHeaders() {
  return {
    Authorization:
      `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,

    "Content-Type":
      "application/json"
  };
}

/* ---------------------------------------------------------
   INITIALIZE PAYSTACK
   --------------------------------------------------------- */

app.post(
  "/api/paystack/init",
  requireLogin,
  async (req, res) => {
    try {
      if (
        !process.env.PAYSTACK_SECRET_KEY
      ) {
        return res.status(500).json({
          success: false,
          message:
            "Paystack secret key is not configured."
        });
      }

      const orderNumber =
        cleanText(
          req.body.order_number
        );

      const order =
        getOrderForUser(
          orderNumber,
          req.session.userId
        );

      if (!order) {
        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      if (
        order.payment_status ===
        "paid"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "This order is already paid."
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

      const user = db
        .prepare(
          `
          SELECT *
          FROM users
          WHERE id = ?
          `
        )
        .get(
          req.session.userId
        );

      if (!user) {
        return res.status(401).json({
          success: false,
          message:
            "User account not found."
        });
      }

      /*
        Paystack requires amount
        in currency subunits.
      */

      const amountSubunit =
        Math.round(
          Number(
            order.amount_kes
          ) * 100
        );

      if (
        amountSubunit <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid order amount."
        });
      }

      const callbackUrl =
        `${getBaseUrl(req)}/?payment=paystack&reference=${encodeURIComponent(order.order_number)}`;

      const channelsRaw =
        String(
          process.env.PAYSTACK_CHANNELS ||
            ""
        )
          .split(",")
          .map((x) =>
            x.trim()
          )
          .filter(Boolean);

      const payload = {
        email: user.email,

        amount:
          String(
            amountSubunit
          ),

        currency:
          process.env.PAYSTACK_CURRENCY ||
          "KES",

        reference:
          order.order_number,

        callback_url:
          callbackUrl,

        metadata: JSON.stringify({
          order_number:
            order.order_number,

          user_id:
            req.session.userId,

          product_id:
            order.product_id
        })
      };

      if (
        channelsRaw.length
      ) {
        payload.channels =
          channelsRaw;
      }

      const response =
        await axios.post(
          `${PAYSTACK_URL}/transaction/initialize`,
          payload,
          {
            headers:
              paystackHeaders(),

            timeout: 20000
          }
        );

      if (
        !response.data ||
        !response.data.status ||
        !response.data.data
      ) {
        throw new Error(
          response.data?.message ||
          "Paystack initialization failed."
        );
      }

      const paystackData =
        response.data.data;

      db.prepare(
        `
        UPDATE orders
        SET paystack_reference = ?
        WHERE id = ?
        `
      ).run(
        paystackData.reference ||
          order.order_number,
        order.id
      );

      res.json({
        success: true,

        authorization_url:
          paystackData.authorization_url,

        access_code:
          paystackData.access_code,

        reference:
          paystackData.reference
      });
    } catch (error) {
      console.error(
        "PAYSTACK INIT ERROR:",
        error.response?.data ||
          error.message
      );

      res.status(500).json({
        success: false,
        message:
          error.response?.data?.message ||
          error.message ||
          "Paystack initialization failed."
      });
    }
  }
);

/* ---------------------------------------------------------
   VERIFY PAYSTACK
   --------------------------------------------------------- */

async function verifyPaystackReference(
  reference
) {
  if (
    !process.env.PAYSTACK_SECRET_KEY
  ) {
    throw new Error(
      "Paystack secret key is not configured."
    );
  }

  const response =
    await axios.get(
      `${PAYSTACK_URL}/transaction/verify/${encodeURIComponent(reference)}`,
      {
        headers:
          paystackHeaders(),

        timeout: 20000
      }
    );

  return response.data;
}

async function markPaystackPaid(
  reference
) {
  const order = db
    .prepare(
      `
      SELECT *
      FROM orders
      WHERE
        order_number = ?
        OR paystack_reference = ?
      LIMIT 1
      `
    )
    .get(
      reference,
      reference
    );

  if (!order) {
    return {
      success: false,
      message:
        "Order not found."
    };
  }

  const result =
    await verifyPaystackReference(
      reference
    );

  const payment =
    result?.data;

  if (
    !result?.status ||
    !payment
  ) {
    return {
      success: false,
      message:
        result?.message ||
        "Paystack verification failed."
    };
  }

  const expectedAmount =
    Math.round(
      Number(
        order.amount_kes
      ) * 100
    );

  const receivedAmount =
    Number(
      payment.amount || 0
    );

  const expectedCurrency =
    String(
      process.env.PAYSTACK_CURRENCY ||
        "KES"
    ).toUpperCase();

  const receivedCurrency =
    String(
      payment.currency ||
        ""
    ).toUpperCase();

  if (
    String(
      payment.reference
    ) !==
      String(
        order.paystack_reference ||
          order.order_number
      )
  ) {
    return {
      success: false,
      message:
        "Payment reference mismatch."
    };
  }

  if (
    payment.status !==
    "success"
  ) {
    return {
      success: false,
      message:
        `Payment status: ${payment.status || "unknown"}`
    };
  }

  if (
    receivedAmount !==
    expectedAmount
  ) {
    return {
      success: false,
      message:
        "Payment amount does not match the order."
    };
  }

  if (
    expectedCurrency &&
    receivedCurrency !==
      expectedCurrency
  ) {
    return {
      success: false,
      message:
        "Payment currency does not match the order."
    };
  }

  /*
    Prevent duplicate fulfillment.
  */

  if (
    order.payment_status !==
    "paid"
  ) {
    db.prepare(
      `
      UPDATE orders
      SET
        payment_status = 'paid',
        paystack_reference = ?,
        paystack_transaction_id = ?,
        paystack_receipt = ?,
        paid_at = CURRENT_TIMESTAMP
      WHERE id = ?
      `
    ).run(
      String(
        payment.reference ||
          reference
      ),

      String(
        payment.id ||
          ""
      ),

      String(
        payment.receipt_number ||
          ""
      ),

      order.id
    );
  }

  return {
    success: true,
    paid: true,
    orderNumber:
      order.order_number
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
          req.session.userId
        );

      if (!order) {
        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      const result =
        await markPaystackPaid(
          reference
        );

      res.json(result);
    } catch (error) {
      console.error(
        "PAYSTACK VERIFY ERROR:",
        error.response?.data ||
          error.message
      );

      res.status(500).json({
        success: false,
        message:
          error.response?.data?.message ||
          error.message ||
          "Unable to verify Paystack payment."
      });
    }
  }
);

/* ---------------------------------------------------------
   PAYSTACK WEBHOOK
   --------------------------------------------------------- */

app.post(
  "/api/paystack/webhook",
  async (req, res) => {
    try {
      const signature =
        req.headers[
          "x-paystack-signature"
        ];

      if (
        !signature ||
        !process.env.PAYSTACK_SECRET_KEY
      ) {
        return res.sendStatus(401);
      }

      const raw =
        req.rawBody ||
        Buffer.from(
          JSON.stringify(req.body)
        );

      const expected =
        crypto
          .createHmac(
            "sha512",
            process.env.PAYSTACK_SECRET_KEY
          )
          .update(raw)
          .digest("hex");

      const valid =
        signature.length ===
          expected.length &&
        crypto.timingSafeEqual(
          Buffer.from(
            signature
          ),
          Buffer.from(
            expected
          )
        );

      if (!valid) {
        return res.sendStatus(401);
      }

      const event =
        req.body;

      if (
        event &&
        event.event ===
          "charge.success"
      ) {
        const reference =
          event.data?.reference;

        if (reference) {
          try {
            await markPaystackPaid(
              reference
            );
          } catch (error) {
            console.error(
              "PAYSTACK WEBHOOK VERIFY ERROR:",
              error.message
            );
          }
        }
      }

      return res.sendStatus(200);
    } catch (error) {
      console.error(
        "PAYSTACK WEBHOOK ERROR:",
        error
      );

      return res.sendStatus(500);
    }
  }
);

/* =========================================================
   BINANCE PAY
   ========================================================= */

const BINANCE_BASE_URL =
  "https://bpay.binanceapi.com";

function binanceHeaders(
  bodyString
) {
  const timestamp =
    Date.now().toString();

  const nonce =
    crypto
      .randomBytes(16)
      .toString("hex")
      .slice(0, 32);

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
        process.env
          .BINANCE_PAY_SECRET_KEY
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
      process.env
        .BINANCE_PAY_CERTIFICATE_SN,

    "BinancePay-Signature":
      signature
  };
}

async function binanceRequest(
  endpoint,
  body
) {
  if (
    !process.env
      .BINANCE_PAY_SECRET_KEY ||
    !process.env
      .BINANCE_PAY_CERTIFICATE_SN
  ) {
    throw new Error(
      "Binance Pay credentials are not configured."
    );
  }

  const bodyString =
    JSON.stringify(body);

  const response =
    await axios.post(
      `${BINANCE_BASE_URL}${endpoint}`,
      bodyString,
      {
        headers:
          binanceHeaders(
            bodyString
          ),

        timeout: 20000
      }
    );

  return response.data;
}

/* ---------------------------------------------------------
   CREATE BINANCE ORDER
   --------------------------------------------------------- */

app.post(
  "/api/binance/create",
  requireLogin,
  async (req, res) => {
    try {
      const orderNumber =
        cleanText(
          req.body.order_number
        );

      const order =
        getOrderForUser(
          orderNumber,
          req.session.userId
        );

      if (!order) {
        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      if (
        order.payment_status ===
        "paid"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Order is already paid."
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

      const merchantTradeNo =
        order.binance_merchant_trade_no ||
        makeBinanceTradeNo();

      const baseUrl =
        getBaseUrl(req);

      /*
        Current Binance Pay integrations
        may use different create-order
        paths depending on merchant API
        configuration.

        Configure with:
        BINANCE_CREATE_PATH
      */

      const createPath =
        process.env
          .BINANCE_CREATE_PATH ||
        "/binancepay/openapi/order";

      const body = {
        env: {
          terminalType:
            "WEB"
        },

        merchantTradeNo,

        orderAmount:
          Number(
            amount.toFixed(8)
          ),

        currency:
          process.env
            .BINANCE_CURRENCY ||
          "USDT",

        goods: {
          goodsType:
            "01",

          goodsCategory:
            "0000",

          referenceGoodsId:
            String(
              order.product_id
            ),

          goodsName:
            String(
              order.product_name ||
                "Digital Product"
            ).slice(0, 256),

          goodsUnitAmount: {
            currency:
              process.env
                .BINANCE_CURRENCY ||
              "USDT",

            amount:
              Number(
                amount.toFixed(8)
              )
          }
        },

        returnUrl:
          `${baseUrl}/?payment=binance&order=${encodeURIComponent(order.order_number)}`,

        cancelUrl:
          `${baseUrl}/?payment=binance_cancelled&order=${encodeURIComponent(order.order_number)}`,

        passThroughInfo:
          order.order_number
      };

      const result =
        await binanceRequest(
          createPath,
          body
        );

      if (
        result.status !==
          "SUCCESS" ||
        !result.data
      ) {
        throw new Error(
          result.errorMessage ||
          "Binance order creation failed."
        );
      }

      const data =
        result.data;

      db.prepare(
        `
        UPDATE orders
        SET
          binance_merchant_trade_no = ?,
          binance_prepay_id = ?
        WHERE id = ?
        `
      ).run(
        merchantTradeNo,

        String(
          data.prepayId ||
            ""
        ),

        order.id
      );

      res.json({
        success: true,

        merchantTradeNo,

        prepayId:
          data.prepayId || "",

        checkoutUrl:
          data.checkoutUrl ||
          data.qrcodeLink ||
          data.qrContent ||
          data.deeplink ||
          ""
      });
    } catch (error) {
      console.error(
        "BINANCE CREATE ERROR:",
        error.response?.data ||
          error.message
      );

      res.status(500).json({
        success: false,
        message:
          error.response?.data
            ?.errorMessage ||
          error.message ||
          "Unable to create Binance payment."
      });
    }
  }
);

/* ---------------------------------------------------------
   QUERY BINANCE ORDER
   --------------------------------------------------------- */

async function queryBinanceOrder(
  merchantTradeNo,
  prepayId
) {
  const queryPath =
    process.env
      .BINANCE_QUERY_PATH ||
    "/binancepay/openapi/order/query";

  return binanceRequest(
    queryPath,
    {
      merchantTradeNo:
        merchantTradeNo ||
        null,

      prepayId:
        prepayId ||
        null
    }
  );
}

async function verifyBinanceOrder(
  order
) {
  const result =
    await queryBinanceOrder(
      order.binance_merchant_trade_no,
      order.binance_prepay_id
    );

  if (
    result.status !==
      "SUCCESS" ||
    !result.data
  ) {
    return {
      success: false,

      message:
        result.errorMessage ||
        "Binance order verification failed."
    };
  }

  const data =
    result.data;

  const expectedAmount =
    Number(
      Number(
        order.amount_crypto
      ).toFixed(8)
    );

  const receivedAmount =
    Number(
      data.totalFee || 0
    );

  const expectedCurrency =
    String(
      process.env
        .BINANCE_CURRENCY ||
        "USDT"
    ).toUpperCase();

  const receivedCurrency =
    String(
      data.currency ||
        ""
    ).toUpperCase();

  if (
    data.merchantTradeNo !==
    order.binance_merchant_trade_no
  ) {
    return {
      success: false,
      message:
        "Binance merchant trade number mismatch."
    };
  }

  if (
    data.status !==
    "PAID"
  ) {
    return {
      success: true,

      paid: false,

      status:
        data.status ||
        "UNKNOWN",

      message:
        `Binance payment status: ${data.status || "UNKNOWN"}`
    };
  }

  if (
    Math.abs(
      receivedAmount -
        expectedAmount
    ) > 0.00000001
  ) {
    return {
      success: false,
      message:
        "Binance payment amount does not match."
    };
  }

  if (
    receivedCurrency !==
    expectedCurrency
  ) {
    return {
      success: false,
      message:
        "Binance payment currency does not match."
    };
  }

  if (
    order.payment_status !==
    "paid"
  ) {
    db.prepare(
      `
      UPDATE orders
      SET
        payment_status = 'paid',
        binance_verified = 1,
        binance_transaction_id = ?,
        binance_prepay_id = ?,
        paid_at = CURRENT_TIMESTAMP
      WHERE id = ?
      `
    ).run(
      String(
        data.transactionId ||
          ""
      ),

      String(
        data.prepayId ||
          order.binance_prepay_id ||
          ""
      ),

      order.id
    );
  }

  return {
    success: true,

    paid: true,

    status: "PAID",

    transactionId:
      data.transactionId ||
      "",

    orderNumber:
      order.order_number
  };
}

/* ---------------------------------------------------------
   CHECK BINANCE PAYMENT
   --------------------------------------------------------- */

app.get(
  "/api/binance/check/:orderNumber",
  requireLogin,
  async (req, res) => {
    try {
      const order =
        getOrderForUser(
          req.params.orderNumber,
          req.session.userId
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

      if (
        !order.binance_merchant_trade_no &&
        !order.binance_prepay_id
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Binance payment has not been initialized."
        });
      }

      const result =
        await verifyBinanceOrder(
          order
        );

      res.json(result);
    } catch (error) {
      console.error(
        "BINANCE CHECK ERROR:",
        error.response?.data ||
          error.message
      );

      res.status(500).json({
        success: false,
        message:
          error.response?.data
            ?.errorMessage ||
          error.message ||
          "Unable to check Binance payment."
      });
    }
  }
);

/* =========================================================
   BINANCE WEBHOOK
   ========================================================= */

app.post(
  "/api/binance/webhook",
  async (req, res) => {
    try {
      /*
        Binance may send notification data
        containing merchantTradeNo/prepayId.

        We do NOT trust the notification
        alone for payment fulfillment.

        Instead, after receiving the
        notification, we query Binance's
        API and verify the real order status.
      */

      const body =
        req.body || {};

      const merchantTradeNo =
        cleanText(
          body.merchantTradeNo ||
          body.data?.merchantTradeNo ||
          body.bizContent?.merchantTradeNo
        );

      const prepayId =
        cleanText(
          body.prepayId ||
          body.data?.prepayId ||
          body.bizContent?.prepayId
        );

      if (
        !merchantTradeNo &&
        !prepayId
      ) {
        return res.sendStatus(200);
      }

      const order = db
        .prepare(
          `
          SELECT *
          FROM orders
          WHERE
            binance_merchant_trade_no = ?
            OR binance_prepay_id = ?
          LIMIT 1
          `
        )
        .get(
          merchantTradeNo,
          prepayId
        );

      if (order) {
        try {
          await verifyBinanceOrder(
            order
          );
        } catch (error) {
          console.error(
            "BINANCE WEBHOOK QUERY ERROR:",
            error.message
          );
        }
      }

      return res.sendStatus(200);
    } catch (error) {
      console.error(
        "BINANCE WEBHOOK ERROR:",
        error
      );

      return res.sendStatus(500);
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
        .prepare(
          `
          SELECT
            id,
            name,
            email,
            is_admin,
            created_at
          FROM users
          ORDER BY id DESC
          `
        )
        .all();

      res.json({
        success: true,
        users
      });
    } catch (error) {
      console.error(
        "ADMIN USERS ERROR:",
        error
      );

      res.status(500).json({
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
        .prepare(
          `
          SELECT
            o.*,

            u.name AS customer_name,
            u.email AS customer_email,

            p.name AS product_name,
            p.image_url AS product_image

          FROM orders o

          JOIN users u
            ON u.id = o.user_id

          JOIN products p
            ON p.id = o.product_id

          ORDER BY o.id DESC
          `
        )
        .all();

      res.json({
        success: true,
        orders
      });
    } catch (error) {
      console.error(
        "ADMIN ORDERS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load orders."
      });
    }
  }
);

/* =========================================================
   ADMIN CHECK PAYMENT
   ========================================================= */

app.post(
  "/api/admin/orders/:orderNumber/check-payment",
  requireAdmin,
  async (req, res) => {
    try {
      const order = db
        .prepare(
          `
          SELECT *
          FROM orders
          WHERE order_number = ?
          `
        )
        .get(
          req.params.orderNumber
        );

      if (!order) {
        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      if (
        order.payment_method ===
        "paystack"
      ) {
        const reference =
          order.paystack_reference ||
          order.order_number;

        const result =
          await markPaystackPaid(
            reference
          );

        return res.json(
          result
        );
      }

      if (
        order.payment_method ===
        "binance"
      ) {
        const result =
          await verifyBinanceOrder(
            order
          );

        return res.json(
          result
        );
      }

      return res.status(400).json({
        success: false,
        message:
          "Unsupported payment method."
      });
    } catch (error) {
      console.error(
        "ADMIN PAYMENT CHECK ERROR:",
        error.response?.data ||
          error.message
      );

      res.status(500).json({
        success: false,
        message:
          error.response?.data
            ?.message ||
          error.message ||
          "Payment check failed."
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
      const order =
        db.prepare(
          `
          SELECT *
          FROM orders
          WHERE order_number = ?
          `
        ).get(
          req.params.orderNumber
        );

      if (!order) {
        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      if (
        order.payment_status !==
        "paid"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Order must be paid before delivery."
        });
      }

      const deliveryStatus =
        cleanText(
          req.body.delivery_status
        ).toLowerCase();

      const deliveryNotes =
        cleanText(
          req.body.delivery_notes
        );

      const allowed = [
        "pending",
        "processing",
        "delivered"
      ];

      if (
        !allowed.includes(
          deliveryStatus
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid delivery status."
        });
      }

      if (
        deliveryStatus ===
        "delivered"
      ) {
        db.prepare(
          `
          UPDATE orders
          SET
            delivery_status = ?,
            delivery_notes = ?,
            delivered_at = CURRENT_TIMESTAMP
          WHERE order_number = ?
          `
        ).run(
          deliveryStatus,
          deliveryNotes,
          order.order_number
        );
      } else {
        db.prepare(
          `
          UPDATE orders
          SET
            delivery_status = ?,
            delivery_notes = ?
          WHERE order_number = ?
          `
        ).run(
          deliveryStatus,
          deliveryNotes,
          order.order_number
        );
      }

      res.json({
        success: true,
        message:
          "Delivery status updated."
      });
    } catch (error) {
      console.error(
        "DELIVERY UPDATE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to update delivery."
      });
    }
  }
);

/* =========================================================
   ADMIN STATS
   ========================================================= */

app.get(
  "/api/admin/stats",
  requireAdmin,
  (req, res) => {
    try {
      const products =
        db
          .prepare(
            `
            SELECT COUNT(*) AS count
            FROM products
            `
          )
          .get()
          .count;

      const activeProducts =
        db
          .prepare(
            `
            SELECT COUNT(*) AS count
            FROM products
            WHERE active = 1
            `
          )
          .get()
          .count;

      const users =
        db
          .prepare(
            `
            SELECT COUNT(*) AS count
            FROM users
            `
          )
          .get()
          .count;

      const orders =
        db
          .prepare(
            `
            SELECT COUNT(*) AS count
            FROM orders
            `
          )
          .get()
          .count;

      const paid =
        db
          .prepare(
            `
            SELECT COUNT(*) AS count
            FROM orders
            WHERE payment_status = 'paid'
            `
          )
          .get()
          .count;

      const revenue =
        db
          .prepare(
            `
            SELECT
              COALESCE(
                SUM(amount_kes),
                0
              ) AS total
            FROM orders
            WHERE payment_status = 'paid'
            AND payment_method = 'paystack'
            `
          )
          .get()
          .total;

      const cryptoRevenue =
        db
          .prepare(
            `
            SELECT
              COALESCE(
                SUM(amount_crypto),
                0
              ) AS total
            FROM orders
            WHERE payment_status = 'paid'
            AND payment_method = 'binance'
            `
          )
          .get()
          .total;

      res.json({
        success: true,

        stats: {
          products,
          activeProducts,
          users,
          orders,
          paid,
          revenueKes:
            money(revenue),
          revenueUsdt:
            Number(
              Number(
                cryptoRevenue
              ).toFixed(8)
            )
        }
      });
    } catch (error) {
      console.error(
        "ADMIN STATS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load statistics."
      });
    }
  }
);

/* =========================================================
   HEALTH CHECK
   ========================================================= */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      success: true,

      status: "online",

      service:
        "DARK WEB STORE",

      time:
        new Date().toISOString(),

      payments: {
        paystack:
          Boolean(
            process.env
              .PAYSTACK_SECRET_KEY
          ),

        binance:
          Boolean(
            process.env
              .BINANCE_PAY_SECRET_KEY &&
            process.env
              .BINANCE_PAY_CERTIFICATE_SN
          )
      }
    });
  }
);

/* =========================================================
   404 API
   ========================================================= */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        "API endpoint not found."
    });
  }
);

/* =========================================================
   FRONTEND FALLBACK
   Express 5 uses named wildcard syntax.
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
   ERROR HANDLER
   ========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    if (
      error instanceof
      multer.MulterError
    ) {
      return res.status(400).json({
        success: false,
        message:
          error.message
      });
    }

    if (
      error &&
      error.message &&
      error.message.includes(
        "Only JPG, PNG"
      )
    ) {
      return res.status(400).json({
        success: false,
        message:
          error.message
      });
    }

    if (
      res.headersSent
    ) {
      return next(error);
    }

    res.status(500).json({
      success: false,
      message:
        "Internal server error."
    });
  }
);

/* =========================================================
   START
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
      adminEmail
    );

    console.log(
      "PAYSTACK:",
      process.env
        .PAYSTACK_SECRET_KEY
        ? "CONFIGURED"
        : "NOT CONFIGURED"
    );

    console.log(
      "BINANCE:",
      process.env
        .BINANCE_PAY_SECRET_KEY
        ? "CONFIGURED"
        : "NOT CONFIGURED"
    );

    console.log(
      "======================================"
    );
  }
);
