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
const UPLOAD_DIR = path.join(
  PUBLIC_DIR,
  "uploads",
  "products"
);

fs.mkdirSync(UPLOAD_DIR, {
  recursive: true
});

/* =========================================================
   EXPRESS
========================================================= */

app.use(express.json({
  limit: "10mb"
}));

app.use(express.urlencoded({
  extended: true,
  limit: "10mb"
}));

/* =========================================================
   SESSION
========================================================= */

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
    path.join(PUBLIC_DIR, "uploads")
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
  path.join(ROOT, "darkweb.db");

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");

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
  price_kes REAL DEFAULT 0,
  binance_price TEXT DEFAULT '',
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
  amount_crypto TEXT DEFAULT '',

  payment_method TEXT NOT NULL,
  payment_status TEXT DEFAULT 'pending',

  delivery_method TEXT DEFAULT 'email',
  delivery_target TEXT DEFAULT '',
  phone TEXT DEFAULT '',

  binance_txid TEXT DEFAULT '',
  binance_verified INTEGER DEFAULT 0,

  checkout_request_id TEXT DEFAULT '',
  merchant_request_id TEXT DEFAULT '',
  mpesa_receipt TEXT DEFAULT '',

  delivery_status TEXT DEFAULT 'pending',
  delivery_notes TEXT DEFAULT '',

  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  paid_at TEXT DEFAULT '',
  delivered_at TEXT DEFAULT ''
);
`);

/* =========================================================
   MIGRATION
========================================================= */

try {
  db.prepare(
    "ALTER TABLE products ADD COLUMN image_url TEXT DEFAULT ''"
  ).run();
} catch (err) {
  // Column already exists
}

/* =========================================================
   ADMIN ACCOUNT
========================================================= */

const adminEmail =
  String(
    process.env.ADMIN_EMAIL ||
      "admin@example.com"
  )
    .trim()
    .toLowerCase();

const adminPassword =
  String(
    process.env.ADMIN_PASSWORD ||
      "ChangeMe123!"
  );

if (adminPassword.length < 6) {
  throw new Error(
    "ADMIN_PASSWORD must contain at least 6 characters."
  );
}

const passwordHash =
  bcrypt.hashSync(adminPassword, 12);

const existingAdmin = db
  .prepare(
    "SELECT * FROM users WHERE email = ?"
  )
  .get(adminEmail);

if (!existingAdmin) {

  db.prepare(`
    INSERT INTO users
    (name, email, password_hash, is_admin)
    VALUES (?, ?, ?, 1)
  `).run(
    "Administrator",
    adminEmail,
    passwordHash
  );

  console.log(
    "ADMIN CREATED:",
    adminEmail
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
    passwordHash,
    adminEmail
  );

  console.log(
    "ADMIN UPDATED:",
    adminEmail
  );
}

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
        cb(null, UPLOAD_DIR);
      },

    filename:
      function (
        req,
        file,
        cb
      ) {

        const ext =
          path.extname(
            file.originalname
          );

        const name =
          crypto
            .randomBytes(12)
            .toString("hex");

        cb(
          null,
          name + ext
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
          cb(null, true);
        } else {
          cb(
            new Error(
              "Only image files are allowed."
            )
          );
        }
      }
  });

/* =========================================================
   HELPERS
========================================================= */

function cleanEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

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
    Number(
      req.session.user.is_admin
    ) !== 1
  ) {

    return res.status(403).json({
      success: false,
      message: "Admin access required."
    });
  }

  next();
}

function makeOrderNumber() {

  return (
    "DW-" +
    Date.now() +
    "-" +
    crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase()
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
        String(
          req.body.name || ""
        ).trim();

      const email =
        cleanEmail(
          req.body.email
        );

      const password =
        String(
          req.body.password || ""
        );

      if (
        !name ||
        !email ||
        !password
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Name, email and password are required."
        });
      }

      if (
        password.length < 6
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Password must contain at least 6 characters."
        });
      }

      const existing =
        db.prepare(
          "SELECT id FROM users WHERE email = ?"
        ).get(email);

      if (existing) {

        return res.status(400).json({
          success: false,
          message:
            "An account with this email already exists."
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        db.prepare(`
          INSERT INTO users
          (name, email, password_hash, is_admin)
          VALUES (?, ?, ?, 0)
        `).run(
          name,
          email,
          hash
        );

      const user = {
        id: result.lastInsertRowid,
        name,
        email,
        is_admin: 0
      };

      req.session.user =
        user;

      res.json({
        success: true,
        user
      });

    } catch (error) {

      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
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
        cleanEmail(
          req.body.email
        );

      const password =
        String(
          req.body.password || ""
        );

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

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(email);

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

      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        is_admin:
          Number(user.is_admin)
      };

      res.json({
        success: true,
        user:
          req.session.user
      });

    } catch (error) {

      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Login failed."
      });
    }
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/me",
  (req, res) => {

    res.json({
      success: true,
      user:
        req.session.user ||
        null
    });
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/logout",
  (req, res) => {

    req.session.destroy(
      () => {

        res.json({
          success: true
        });

      }
    );
  }
);

/* =========================================================
   PRODUCTS - PUBLIC
========================================================= */

app.get(
  "/api/products",
  (req, res) => {

    try {

      const products =
        db.prepare(`
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
        `).all();

      res.json({
        success: true,
        products
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Could not load products."
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

    res.json({
      success: true,
      products
    });
  }
);

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
        String(
          req.body.name || ""
        ).trim();

      const description =
        String(
          req.body.description || ""
        ).trim();

      const priceKes =
        Number(
          req.body.price_kes || 0
        );

      const binancePrice =
        String(
          req.body.binance_price || ""
        ).trim();

      const deliveryContent =
        String(
          req.body.delivery_content || ""
        );

      if (!name) {

        return res.status(400).json({
          success: false,
          message:
            "Product name is required."
        });
      }

      const imageUrl =
        req.file
          ? "/uploads/products/" +
            req.file.filename
          : "";

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
          VALUES (?, ?, ?, ?, ?, ?, 1)
        `).run(
          name,
          description,
          priceKes,
          binancePrice,
          deliveryContent,
          imageUrl
        );

      res.json({
        success: true,
        productId:
          result.lastInsertRowid
      });

    } catch (error) {

      console.error(
        "ADD PRODUCT ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Could not create product."
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

    const id =
      Number(req.params.id);

    const product =
      db.prepare(
        "SELECT active FROM products WHERE id = ?"
      ).get(id);

    if (!product) {

      return res.status(404).json({
        success: false,
        message:
          "Product not found."
      });
    }

    db.prepare(`
      UPDATE products
      SET active = ?
      WHERE id = ?
    `).run(
      product.active ? 0 : 1,
      id
    );

    res.json({
      success: true
    });
  }
);

/* =========================================================
   ADMIN DELETE PRODUCT
========================================================= */

app.delete(
  "/api/admin/products/:id",
  requireAdmin,
  (req, res) => {

    const id =
      Number(req.params.id);

    db.prepare(
      "DELETE FROM products WHERE id = ?"
    ).run(id);

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

      const paymentMethod =
        String(
          req.body.payment_method || ""
        ).trim();

      const deliveryMethod =
        String(
          req.body.delivery_method ||
            "email"
        ).trim();

      const deliveryTarget =
        String(
          req.body.delivery_target ||
            ""
        ).trim();

      const phone =
        String(
          req.body.phone || ""
        ).trim();

      const product =
        db.prepare(`
          SELECT *
          FROM products
          WHERE id = ?
          AND active = 1
        `).get(productId);

      if (!product) {

        return res.status(404).json({
          success: false,
          message:
            "Product not found."
        });
      }

      if (
        ![
          "mpesa",
          "binance"
        ].includes(
          paymentMethod
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Invalid payment method."
        });
      }

      if (!deliveryTarget) {

        return res.status(400).json({
          success: false,
          message:
            "Delivery target is required."
        });
      }

      const orderNumber =
        makeOrderNumber();

      const amountKes =
        Number(
          product.price_kes || 0
        );

      const amountCrypto =
        String(
          product.binance_price || ""
        );

      const result =
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
            phone
          )
          VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
        `).run(
          orderNumber,
          req.session.user.id,
          productId,
          amountKes,
          amountCrypto,
          paymentMethod,
          deliveryMethod,
          deliveryTarget,
          phone
        );

      res.json({
        success: true,
        order: {
          id:
            result.lastInsertRowid,
          order_number:
            orderNumber,
          amount_kes:
            amountKes,
          amount_crypto:
            amountCrypto,
          payment_method:
            paymentMethod,
          payment_status:
            "pending"
        }
      });

    } catch (error) {

      console.error(
        "ORDER ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Could not create order."
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

    const orders =
      db.prepare(`
        SELECT
          o.*,
          p.name AS product_name,
          p.image_url
        FROM orders o
        LEFT JOIN products p
          ON p.id = o.product_id
        WHERE o.user_id = ?
        ORDER BY o.id DESC
      `).all(
        req.session.user.id
      );

    res.json({
      success: true,
      orders
    });
  }
);

/* =========================================================
   SINGLE ORDER
========================================================= */

app.get(
  "/api/orders/:id",
  requireLogin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const order =
      db.prepare(`
        SELECT
          o.*,
          p.name AS product_name,
          p.description,
          p.image_url,
          p.delivery_content
        FROM orders o
        LEFT JOIN products p
          ON p.id = o.product_id
        WHERE o.id = ?
        AND o.user_id = ?
      `).get(
        id,
        req.session.user.id
      );

    if (!order) {

      return res.status(404).json({
        success: false,
        message:
          "Order not found."
      });
    }

    res.json({
      success: true,
      order
    });
  }
);

/* =========================================================
   BINANCE PAYMENT INFO
========================================================= */

app.get(
  "/api/payment/binance",
  requireLogin,
  (req, res) => {

    res.json({
      success: true,

      wallet:
        process.env.BINANCE_USDT_ADDRESS ||
        "",

      network:
        process.env.BINANCE_NETWORK ||
        "TRC20",

      instructions:
        "Send the exact USDT amount to the wallet, then submit your transaction hash."
    });
  }
);

/* =========================================================
   BINANCE TXID
========================================================= */

app.post(
  "/api/orders/:id/binance",
  requireLogin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const txid =
      String(
        req.body.txid || ""
      ).trim();

    if (!txid) {

      return res.status(400).json({
        success: false,
        message:
          "Transaction hash is required."
      });
    }

    const order =
      db.prepare(`
        SELECT *
        FROM orders
        WHERE id = ?
        AND user_id = ?
      `).get(
        id,
        req.session.user.id
      );

    if (!order) {

      return res.status(404).json({
        success: false,
        message:
          "Order not found."
      });
    }

    db.prepare(`
      UPDATE orders
      SET
        binance_txid = ?,
        payment_status = 'verification_pending'
      WHERE id = ?
    `).run(
      txid,
      id
    );

    res.json({
      success: true,
      message:
        "Transaction submitted for admin verification."
    });
  }
);

/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
  "/api/admin/orders",
  requireAdmin,
  (req, res) => {

    const orders =
      db.prepare(`
        SELECT
          o.*,
          u.name AS customer_name,
          u.email AS customer_email,
          p.name AS product_name
        FROM orders o
        LEFT JOIN users u
          ON u.id = o.user_id
        LEFT JOIN products p
          ON p.id = o.product_id
        ORDER BY o.id DESC
      `).all();

    res.json({
      success: true,
      orders
    });
  }
);

/* =========================================================
   ADMIN VERIFY BINANCE
========================================================= */

app.post(
  "/api/admin/orders/:id/binance-verify",
  requireAdmin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const approved =
      Boolean(
        req.body.approved
      );

    const order =
      db.prepare(
        "SELECT * FROM orders WHERE id = ?"
      ).get(id);

    if (!order) {

      return res.status(404).json({
        success: false,
        message:
          "Order not found."
      });
    }

    if (approved) {

      db.prepare(`
        UPDATE orders
        SET
          binance_verified = 1,
          payment_status = 'paid',
          paid_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(id);

    } else {

      db.prepare(`
        UPDATE orders
        SET
          binance_verified = 0,
          payment_status = 'rejected'
        WHERE id = ?
      `).run(id);
    }

    res.json({
      success: true
    });
  }
);

/* =========================================================
   ADMIN DELIVERY UPDATE
========================================================= */

app.post(
  "/api/admin/orders/:id/delivery",
  requireAdmin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const status =
      String(
        req.body.status || ""
      ).trim();

    const notes =
      String(
        req.body.notes || ""
      ).trim();

    const allowed =
      [
        "pending",
        "processing",
        "delivered",
        "cancelled"
      ];

    if (
      !allowed.includes(status)
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Invalid delivery status."
      });
    }

    if (
      status === "delivered"
    ) {

      db.prepare(`
        UPDATE orders
        SET
          delivery_status = ?,
          delivery_notes = ?,
          delivered_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(
        status,
        notes,
        id
      );

    } else {

      db.prepare(`
        UPDATE orders
        SET
          delivery_status = ?,
          delivery_notes = ?
        WHERE id = ?
      `).run(
        status,
        notes,
        id
      );
    }

    res.json({
      success: true
    });
  }
);

/* =========================================================
   M-PESA CONFIG
========================================================= */

function mpesaConfigured() {

  return Boolean(
    process.env.MPESA_CONSUMER_KEY &&
    process.env.MPESA_CONSUMER_SECRET &&
    process.env.MPESA_SHORTCODE &&
    process.env.MPESA_PASSKEY &&
    process.env.MPESA_CALLBACK_URL
  );
}

/* =========================================================
   M-PESA TOKEN
========================================================= */

async function getMpesaToken() {

  const url =
    process.env.MPESA_ENV === "production"
      ? "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
      : "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials";

  const auth =
    Buffer.from(
      process.env.MPESA_CONSUMER_KEY +
      ":" +
      process.env.MPESA_CONSUMER_SECRET
    ).toString("base64");

  const response =
    await axios.get(
      url,
      {
        headers: {
          Authorization:
            "Basic " + auth
        }
      }
    );

  return response.data.access_token;
}

/* =========================================================
   M-PESA STK
========================================================= */

app.post(
  "/api/orders/:id/mpesa",
  requireLogin,
  async (req, res) => {

    try {

      if (!mpesaConfigured()) {

        return res.status(503).json({
          success: false,
          message:
            "M-Pesa is not configured yet."
        });
      }

      const id =
        Number(req.params.id);

      const phone =
        String(
          req.body.phone || ""
        ).trim();

      if (!phone) {

        return res.status(400).json({
          success: false,
          message:
            "M-Pesa phone number is required."
        });
      }

      const order =
        db.prepare(`
          SELECT *
          FROM orders
          WHERE id = ?
          AND user_id = ?
        `).get(
          id,
          req.session.user.id
        );

      if (!order) {

        return res.status(404).json({
          success: false,
          message:
            "Order not found."
        });
      }

      const token =
        await getMpesaToken();

      const timestamp =
        new Date()
          .toISOString()
          .replace(
            /\D/g,
            ""
          )
          .slice(
            0,
            14
          );

      const password =
        Buffer.from(
          process.env.MPESA_SHORTCODE +
          process.env.MPESA_PASSKEY +
          timestamp
        ).toString(
          "base64"
        );

      const baseUrl =
        process.env.MPESA_ENV === "production"
          ? "https://api.safaricom.co.ke"
          : "https://sandbox.safaricom.co.ke";

      const response =
        await axios.post(
          baseUrl +
            "/mpesa/stkpush/v1/processrequest",
          {
            BusinessShortCode:
              process.env.MPESA_SHORTCODE,

            Password:
              password,

            Timestamp:
              timestamp,

            TransactionType:
              "CustomerPayBillOnline",

            Amount:
              Math.max(
                1,
                Math.round(
                  Number(
                    order.amount_kes
                  )
                )
              ),

            PartyA:
              phone,

            PartyB:
              process.env.MPESA_SHORTCODE,

            PhoneNumber:
              phone,

            CallBackURL:
              process.env.MPESA_CALLBACK_URL,

            AccountReference:
              order.order_number,

            TransactionDesc:
              "DARK WEB purchase"
          },
          {
            headers: {
              Authorization:
                "Bearer " + token
            }
          }
        );

      const data =
        response.data;

      db.prepare(`
        UPDATE orders
        SET
          phone = ?,
          checkout_request_id = ?,
          merchant_request_id = ?,
          payment_status = 'stk_sent'
        WHERE id = ?
      `).run(
        phone,
        data.CheckoutRequestID ||
          "",
        data.MerchantRequestID ||
          "",
        id
      );

      res.json({
        success: true,
        message:
          data.CustomerMessage ||
          "STK Push sent to your phone.",
        data
      });

    } catch (error) {

      console.error(
        "MPESA ERROR:",
        error.response?.data ||
          error.message
      );

      res.status(500).json({
        success: false,
        message:
          "Could not start M-Pesa payment."
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
        Number(
          body.ResultCode
        );

      const order =
        db.prepare(`
          SELECT *
          FROM orders
          WHERE checkout_request_id = ?
        `).get(
          checkoutRequestId
        );

      if (!order) {

        return res.json({
          ResultCode: 0,
          ResultDesc: "Accepted"
        });
      }

      if (resultCode === 0) {

        const metadata =
          body.CallbackMetadata?.Item ||
          [];

        let receipt = "";

        for (
          const item
          of metadata
        ) {

          if (
            item.Name ===
            "MpesaReceiptNumber"
          ) {
            receipt =
              item.Value ||
              "";
          }
        }

        db.prepare(`
          UPDATE orders
          SET
            payment_status = 'paid',
            mpesa_receipt = ?,
            paid_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).run(
          receipt,
          order.id
        );

      } else {

        db.prepare(`
          UPDATE orders
          SET
            payment_status = 'failed'
          WHERE id = ?
        `).run(
          order.id
        );
      }

      res.json({
        ResultCode: 0,
        ResultDesc: "Accepted"
      });

    } catch (error) {

      console.error(
        "MPESA CALLBACK ERROR:",
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
   HEALTH
========================================================= */

app.get(
  "/api/health",
  (req, res) => {

    res.json({
      success: true,
      status: "online",
      app: "DARK WEB STORE",
      time:
        new Date().toISOString()
    });
  }
);

/* =========================================================
   FRONTEND FALLBACK
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

    res.status(500).json({
      success: false,
      message:
        error.message ||
        "Server error."
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
      "======================================"
    );
  }
);
