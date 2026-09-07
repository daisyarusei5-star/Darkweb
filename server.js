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

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   SESSION
========================================================= */

app.set("trust proxy", 1);

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "CHANGE_THIS_SESSION_SECRET",

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure:
        process.env.NODE_ENV === "production",
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
  is_admin INTEGER NOT NULL DEFAULT 0,
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
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_number TEXT NOT NULL UNIQUE,

  user_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,

  amount_kes REAL NOT NULL DEFAULT 0,
  amount_crypto REAL NOT NULL DEFAULT 0,

  payment_method TEXT NOT NULL,
  payment_status TEXT NOT NULL DEFAULT 'pending',

  delivery_method TEXT DEFAULT 'email',
  delivery_target TEXT DEFAULT '',

  phone TEXT DEFAULT '',

  binance_txid TEXT DEFAULT '',
  binance_verified INTEGER NOT NULL DEFAULT 0,

  checkout_request_id TEXT DEFAULT '',
  merchant_request_id TEXT DEFAULT '',
  mpesa_receipt TEXT DEFAULT '',

  delivery_status TEXT NOT NULL DEFAULT 'pending',
  delivery_notes TEXT DEFAULT '',

  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  paid_at TEXT DEFAULT '',
  delivered_at TEXT DEFAULT ''
);
`);

/* =========================================================
   SAFE MIGRATIONS
========================================================= */

function addColumnIfMissing(
  table,
  column,
  definition
) {
  try {
    db.exec(
      `ALTER TABLE ${table}
       ADD COLUMN ${column} ${definition}`
    );
  } catch (error) {
    if (
      !String(error.message).includes(
        "duplicate column"
      )
    ) {
      console.log(
        "Migration:",
        error.message
      );
    }
  }
}

addColumnIfMissing(
  "products",
  "image_url",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "orders",
  "delivery_notes",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "orders",
  "paid_at",
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  "orders",
  "delivered_at",
  "TEXT DEFAULT ''"
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

const existingAdmin = db
  .prepare(
    "SELECT * FROM users WHERE email = ?"
  )
  .get(adminEmail);

const adminHash =
  bcrypt.hashSync(adminPassword, 12);

if (!existingAdmin) {
  db.prepare(`
    INSERT INTO users
    (name, email, password_hash, is_admin)
    VALUES (?, ?, ?, 1)
  `).run(
    "Administrator",
    adminEmail,
    adminHash
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
    adminHash,
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

function cleanEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function cleanText(value) {
  return String(value || "").trim();
}

function makeOrderNumber() {
  const date =
    new Date()
      .toISOString()
      .replace(/\D/g, "")
      .slice(0, 14);

  const random =
    crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase();

  return `DW-${date}-${random}`;
}

function now() {
  return new Date().toISOString();
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
    Number(req.session.user.is_admin) !== 1
  ) {
    return res.status(403).json({
      success: false,
      message: "Admin access required."
    });
  }

  next();
}

/* =========================================================
   IMAGE UPLOAD
========================================================= */

const storage =
  multer.diskStorage({
    destination: (
      req,
      file,
      cb
    ) => {
      cb(null, UPLOAD_DIR);
    },

    filename: (
      req,
      file,
      cb
    ) => {
      const ext =
        path.extname(
          file.originalname
        ).toLowerCase();

      const filename =
        Date.now() +
        "-" +
        crypto
          .randomBytes(5)
          .toString("hex") +
        ext;

      cb(null, filename);
    }
  });

const upload = multer({
  storage,

  limits: {
    fileSize:
      5 * 1024 * 1024
  },

  fileFilter: (
    req,
    file,
    cb
  ) => {
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
        name.length < 2
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Please enter your name."
        });
      }

      if (
        !email.includes("@")
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Please enter a valid email."
        });
      }

      if (
        password.length < 6
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Password must be at least 6 characters."
        });
      }

      const exists =
        db
          .prepare(
            "SELECT id FROM users WHERE email = ?"
          )
          .get(email);

      if (exists) {
        return res.status(409).json({
          success: false,
          message:
            "Email already registered."
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        db
          .prepare(`
            INSERT INTO users
            (name,email,password_hash,is_admin)
            VALUES (?,?,?,0)
          `)
          .run(
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

      console.log(
        "LOGIN ATTEMPT:",
        email
      );

      const user =
        db
          .prepare(
            "SELECT * FROM users WHERE email = ?"
          )
          .get(email);

      if (!user) {
        console.log(
          "LOGIN USER FOUND: false"
        );

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

      console.log(
        "LOGIN USER FOUND: true PASSWORD VALID:",
        valid
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
        user: req.session.user
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
   PUBLIC PRODUCTS
========================================================= */

app.get(
  "/api/products",
  (req, res) => {
    const products =
      db
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
      success: true,
      products
    });
  }
);

/* =========================================================
   CUSTOMER ACCOUNT
========================================================= */

app.get(
  "/api/account",
  requireLogin,
  (req, res) => {
    const user =
      db
        .prepare(`
          SELECT
            id,
            name,
            email,
            is_admin,
            created_at
          FROM users
          WHERE id = ?
        `)
        .get(
          req.session.user.id
        );

    res.json({
      success: true,
      user
    });
  }
);

/* =========================================================
   CUSTOMER ORDERS
========================================================= */

app.get(
  "/api/my-orders",
  requireLogin,
  (req, res) => {
    const orders =
      db
        .prepare(`
          SELECT
            o.*,
            p.name AS product_name,
            p.description AS product_description
          FROM orders o
          LEFT JOIN products p
            ON p.id = o.product_id
          WHERE o.user_id = ?
          ORDER BY o.id DESC
        `)
        .all(
          req.session.user.id
        );

    res.json({
      success: true,
      orders
    });
  }
);

app.get(
  "/api/orders/:id",
  requireLogin,
  (req, res) => {
    const order =
      db
        .prepare(`
          SELECT
            o.*,
            p.name AS product_name,
            p.description AS product_description,
            p.delivery_content
          FROM orders o
          LEFT JOIN products p
            ON p.id = o.product_id
          WHERE o.id = ?
            AND o.user_id = ?
        `)
        .get(
          Number(req.params.id),
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
        cleanText(
          req.body.payment_method
        ).toLowerCase();

      const deliveryTarget =
        cleanText(
          req.body.delivery_target
        );

      const phone =
        cleanText(
          req.body.phone
        );

      const deliveryMethod =
        cleanText(
          req.body.delivery_method ||
            "email"
        );

      const product =
        db
          .prepare(
            "SELECT * FROM products WHERE id = ? AND active = 1"
          )
          .get(productId);

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
            "Select a valid payment method."
        });
      }

      if (
        deliveryTarget.length < 3
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter your delivery email/contact."
        });
      }

      const amountKes =
        Number(
          product.price_kes
        );

      const amountCrypto =
        Number(
          product.binance_price
        );

      const orderNumber =
        makeOrderNumber();

      const result =
        db
          .prepare(`
            INSERT INTO orders (
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
            VALUES (?,?,?,?,?,?,?,?,?,?)
          `)
          .run(
            orderNumber,
            req.session.user.id,
            product.id,
            amountKes,
            amountCrypto,
            paymentMethod,
            "pending",
            deliveryMethod,
            deliveryTarget,
            phone
          );

      const order =
        db
          .prepare(
            "SELECT * FROM orders WHERE id = ?"
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
          "Could not create order."
      });
    }
  }
);

/* =========================================================
   BINANCE INFO
========================================================= */

app.get(
  "/api/binance-info",
  (req, res) => {
    res.json({
      success: true,

      address:
        process.env.BINANCE_USDT_ADDRESS ||
        "",

      network:
        process.env.BINANCE_NETWORK ||
        "TRC20"
    });
  }
);

/* =========================================================
   BINANCE TXID
========================================================= */

app.post(
  "/api/orders/:id/binance-txid",
  requireLogin,
  (req, res) => {
    const txid =
      cleanText(
        req.body.txid
      );

    if (
      txid.length < 8
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Enter a valid transaction hash."
      });
    }

    const order =
      db
        .prepare(`
          SELECT *
          FROM orders
          WHERE id = ?
            AND user_id = ?
        `)
        .get(
          Number(req.params.id),
          req.session.user.id
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

    db.prepare(`
      UPDATE orders
      SET
        binance_txid = ?,
        payment_status = 'payment_submitted'
      WHERE id = ?
    `).run(
      txid,
      order.id
    );

    res.json({
      success: true,
      message:
        "Transaction submitted for admin verification."
    });
  }
);

/* =========================================================
   ADMIN DASHBOARD
========================================================= */

app.get(
  "/api/admin/stats",
  requireAdmin,
  (req, res) => {
    const users =
      db
        .prepare(
          "SELECT COUNT(*) AS count FROM users WHERE is_admin = 0"
        )
        .get().count;

    const products =
      db
        .prepare(
          "SELECT COUNT(*) AS count FROM products WHERE active = 1"
        )
        .get().count;

    const orders =
      db
        .prepare(
          "SELECT COUNT(*) AS count FROM orders"
        )
        .get().count;

    const paid =
      db
        .prepare(`
          SELECT COUNT(*) AS count
          FROM orders
          WHERE payment_status = 'paid'
        `)
        .get().count;

    const revenue =
      db
        .prepare(`
          SELECT
            COALESCE(
              SUM(amount_kes),
              0
            ) AS total
          FROM orders
          WHERE payment_status = 'paid'
        `)
        .get().total;

    res.json({
      success: true,
      stats: {
        users,
        products,
        orders,
        paid,
        revenue
      }
    });
  }
);

/* =========================================================
   ADMIN USERS
========================================================= */

app.get(
  "/api/admin/users",
  requireAdmin,
  (req, res) => {
    const users =
      db
        .prepare(`
          SELECT
            id,
            name,
            email,
            is_admin,
            created_at
          FROM users
          ORDER BY id DESC
        `)
        .all();

    res.json({
      success: true,
      users
    });
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
      db
        .prepare(`
          SELECT *
          FROM products
          ORDER BY id DESC
        `)
        .all();

    res.json({
      success: true,
      products
    });
  }
);

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

      const deliveryContent =
        String(
          req.body.delivery_content ||
            ""
        );

      const priceKes =
        Number(
          req.body.price_kes
        );

      const binancePrice =
        Number(
          req.body.binance_price ||
            0
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
            "Enter a valid KSh price."
        });
      }

      let imageUrl = "";

      if (req.file) {
        imageUrl =
          "/uploads/products/" +
          req.file.filename;
      }

      const result =
        db
          .prepare(`
            INSERT INTO products (
              name,
              description,
              price_kes,
              binance_price,
              delivery_content,
              image_url,
              active
            )
            VALUES (?,?,?,?,?,?,1)
          `)
          .run(
            name,
            description,
            priceKes,
            binancePrice,
            deliveryContent,
            imageUrl
          );

      res.json({
        success: true,
        product:
          db
            .prepare(
              "SELECT * FROM products WHERE id = ?"
            )
            .get(
              result.lastInsertRowid
            )
      });
    } catch (error) {
      console.error(
        "PRODUCT ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message ||
          "Product creation failed."
      });
    }
  }
);

app.post(
  "/api/admin/products/:id/toggle",
  requireAdmin,
  (req, res) => {
    const product =
      db
        .prepare(
          "SELECT * FROM products WHERE id = ?"
        )
        .get(
          Number(req.params.id)
        );

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
      product.id
    );

    res.json({
      success: true
    });
  }
);

app.delete(
  "/api/admin/products/:id",
  requireAdmin,
  (req, res) => {
    const product =
      db
        .prepare(
          "SELECT * FROM products WHERE id = ?"
        )
        .get(
          Number(req.params.id)
        );

    if (!product) {
      return res.status(404).json({
        success: false,
        message:
          "Product not found."
      });
    }

    db.prepare(`
      DELETE FROM products
      WHERE id = ?
    `).run(
      product.id
    );

    res.json({
      success: true
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
      db
        .prepare(`
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
        `)
        .all();

    res.json({
      success: true,
      orders
    });
  }
);

/* =========================================================
   ADMIN BINANCE VERIFY
========================================================= */

app.post(
  "/api/admin/orders/:id/verify-binance",
  requireAdmin,
  (req, res) => {
    const order =
      db
        .prepare(
          "SELECT * FROM orders WHERE id = ?"
        )
        .get(
          Number(req.params.id)
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
        binance_verified = 1,
        payment_status = 'paid',
        paid_at = ?
      WHERE id = ?
    `).run(
      now(),
      order.id
    );

    res.json({
      success: true,
      message:
        "Binance payment marked as paid."
    });
  }
);

/* =========================================================
   ADMIN MARK PAYMENT
========================================================= */

app.post(
  "/api/admin/orders/:id/payment",
  requireAdmin,
  (req, res) => {
    const status =
      cleanText(
        req.body.status
      );

    const allowed = [
      "pending",
      "payment_submitted",
      "paid",
      "failed",
      "cancelled"
    ];

    if (
      !allowed.includes(
        status
      )
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Invalid payment status."
      });
    }

    const order =
      db
        .prepare(
          "SELECT * FROM orders WHERE id = ?"
        )
        .get(
          Number(req.params.id)
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
        payment_status = ?,
        paid_at = CASE
          WHEN ? = 'paid'
          THEN ?
          ELSE paid_at
        END
      WHERE id = ?
    `).run(
      status,
      status,
      now(),
      order.id
    );

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
    const status =
      cleanText(
        req.body.status
      );

    const notes =
      cleanText(
        req.body.notes
      );

    const allowed = [
      "pending",
      "processing",
      "delivered",
      "cancelled"
    ];

    if (
      !allowed.includes(
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
      db
        .prepare(
          "SELECT * FROM orders WHERE id = ?"
        )
        .get(
          Number(req.params.id)
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
        delivery_status = ?,
        delivery_notes = ?,
        delivered_at = CASE
          WHEN ? = 'delivered'
          THEN ?
          ELSE delivered_at
        END
      WHERE id = ?
    `).run(
      status,
      notes,
      status,
      now(),
      order.id
    );

    res.json({
      success: true
    });
  }
);

/* =========================================================
   MPESA
========================================================= */

function mpesaBaseUrl() {
  return (
    process.env.MPESA_ENV ===
    "production"
  )
    ? "https://api.safaricom.co.ke"
    : "https://sandbox.safaricom.co.ke";
}

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

  const auth =
    Buffer.from(
      `${key}:${secret}`
    ).toString(
      "base64"
    );

  const response =
    await axios.get(
      `${mpesaBaseUrl()}/oauth/v1/generate?grant_type=client_credentials`,
      {
        headers: {
          Authorization:
            `Basic ${auth}`
        }
      }
    );

  return response.data.access_token;
}

function mpesaTimestamp() {
  const d = new Date();

  const pad =
    n =>
      String(n).padStart(
        2,
        "0"
      );

  return (
    d.getFullYear() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds())
  );
}

app.post(
  "/api/mpesa/stk",
  requireLogin,
  async (req, res) => {
    try {
      const orderId =
        Number(
          req.body.order_id
        );

      const phone =
        cleanText(
          req.body.phone
        );

      const order =
        db
          .prepare(`
            SELECT *
            FROM orders
            WHERE id = ?
              AND user_id = ?
          `)
          .get(
            orderId,
            req.session.user.id
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
        "mpesa"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "This is not an M-Pesa order."
        });
      }

      if (!phone) {
        return res.status(400).json({
          success: false,
          message:
            "Enter your M-Pesa phone number."
        });
      }

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
          success: false,
          message:
            "M-Pesa is not fully configured in Render."
        });
      }

      const token =
        await getMpesaToken();

      const timestamp =
        mpesaTimestamp();

      const password =
        Buffer.from(
          shortcode +
          passkey +
          timestamp
        ).toString(
          "base64"
        );

      const amount =
        Math.round(
          Number(
            order.amount_kes
          )
        );

      const response =
        await axios.post(
          `${mpesaBaseUrl()}/mpesa/stkpush/v1/processrequest`,
          {
            BusinessShortCode:
              shortcode,

            Password:
              password,

            Timestamp:
              timestamp,

            TransactionType:
              "CustomerPayBillOnline",

            Amount:
              amount,

            PartyA:
              phone,

            PartyB:
              shortcode,

            PhoneNumber:
              phone,

            CallBackURL:
              callback,

            AccountReference:
              order.order_number,

            TransactionDesc:
              `DARK WEB ${order.order_number}`
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
        SET
          checkout_request_id = ?,
          merchant_request_id = ?,
          phone = ?,
          payment_status = 'payment_submitted'
        WHERE id = ?
      `).run(
        response.data.CheckoutRequestID ||
          "",
        response.data.MerchantRequestID ||
          "",
        phone,
        order.id
      );

      res.json({
        success: true,
        message:
          response.data.CustomerMessage ||
          "Check your phone for the M-Pesa payment prompt."
      });
    } catch (error) {
      console.error(
        "MPESA STK ERROR:",
        error.response?.data ||
          error.message
      );

      res.status(500).json({
        success: false,
        message:
          error.response?.data?.errorMessage ||
          "Could not start M-Pesa payment."
      });
    }
  }
);

/* =========================================================
   MPESA CALLBACK
========================================================= */

app.post(
  "/api/mpesa/callback",
  (req, res) => {
    try {
      const callback =
        req.body?.Body?.stkCallback;

      if (!callback) {
        return res.json({
          ResultCode: 0,
          ResultDesc:
            "Accepted"
        });
      }

      const checkoutId =
        callback.CheckoutRequestID;

      const resultCode =
        Number(
          callback.ResultCode
        );

      const order =
        db
          .prepare(`
            SELECT *
            FROM orders
            WHERE checkout_request_id = ?
          `)
          .get(
            checkoutId
          );

      if (!order) {
        return res.json({
          ResultCode: 0,
          ResultDesc:
            "Accepted"
        });
      }

      if (
        resultCode === 0
      ) {
        const metadata =
          callback.CallbackMetadata
            ?.Item || [];

        let receipt = "";

        for (
          const item of metadata
        ) {
          if (
            item.Name ===
            "MpesaReceiptNumber"
          ) {
            receipt =
              item.Value || "";
          }
        }

        db.prepare(`
          UPDATE orders
          SET
            payment_status = 'paid',
            mpesa_receipt = ?,
            paid_at = ?
          WHERE id = ?
        `).run(
          receipt,
          now(),
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

      return res.json({
        ResultCode: 0,
        ResultDesc:
          "Accepted"
      });
    } catch (error) {
      console.error(
        "MPESA CALLBACK ERROR:",
        error
      );

      res.json({
        ResultCode: 0,
        ResultDesc:
          "Accepted"
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
      service:
        "DARK WEB STORE",
      time: now()
    });
  }
);

/* =========================================================
   SPA FALLBACK - EXPRESS 5
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
      "WHATSAPP:",
      process.env.SUPPORT_WHATSAPP ||
        "254781601410"
    );

    console.log(
      "======================================"
    );
  }
);
