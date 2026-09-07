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

/* =========================================================
   DIRECTORIES
========================================================= */

const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOAD_DIR = path.join(PUBLIC_DIR, "uploads");
const PRODUCT_UPLOAD_DIR = path.join(UPLOAD_DIR, "products");

fs.mkdirSync(PRODUCT_UPLOAD_DIR, {
  recursive: true
});

/* =========================================================
   DATABASE
========================================================= */

const db = new Database(
  process.env.DATABASE_PATH || path.join(__dirname, "darkweb.db")
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
  binance_price REAL NOT NULL,
  delivery_content TEXT DEFAULT '',
  image_url TEXT DEFAULT '',
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_number TEXT UNIQUE NOT NULL,
  user_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  amount_kes REAL NOT NULL,
  amount_crypto REAL NOT NULL,
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
  delivery_status TEXT DEFAULT 'PENDING',
  delivery_notes TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  paid_at TEXT DEFAULT '',
  delivered_at TEXT DEFAULT ''
);
`);

/* =========================================================
   DATABASE MIGRATION
   Adds image_url to old databases
========================================================= */

function addColumnIfMissing(table, column, definition) {
  const columns = db
    .prepare(`PRAGMA table_info(${table})`)
    .all();

  const exists = columns.some(
    c => c.name === column
  );

  if (!exists) {
    db.exec(
      `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
    );
  }
}

addColumnIfMissing(
  "products",
  "image_url",
  "TEXT DEFAULT ''"
);

/* =========================================================
   ADMIN ACCOUNT
========================================================= */

const adminEmail =
  process.env.ADMIN_EMAIL || "admin@example.com";

const adminPassword =
  process.env.ADMIN_PASSWORD || "ChangeMe123!";

const existingAdmin = db
  .prepare(
    "SELECT id FROM users WHERE email = ?"
  )
  .get(adminEmail);

if (!existingAdmin) {
  const hash = bcrypt.hashSync(
    adminPassword,
    12
  );

  db.prepare(`
    INSERT INTO users
    (name, email, password_hash, is_admin)
    VALUES (?, ?, ?, 1)
  `).run(
    "Administrator",
    adminEmail,
    hash
  );

  console.log(
    `Admin created: ${adminEmail}`
  );
}

/* =========================================================
   DEFAULT PRODUCTS
========================================================= */

const productCount = db
  .prepare(
    "SELECT COUNT(*) AS count FROM products"
  )
  .get();

if (productCount.count === 0) {
  const insert = db.prepare(`
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
  `);

  const products = [
    [
      "Item 1",
      "Digital product Item 1",
      500,
      3.5,
      "Replace this with the actual delivery content for Item 1.",
      ""
    ],
    [
      "Item 2",
      "Digital product Item 2",
      1000,
      7,
      "Replace this with the actual delivery content for Item 2.",
      ""
    ],
    [
      "Item 3",
      "Digital product Item 3",
      1500,
      10.5,
      "Replace this with the actual delivery content for Item 3.",
      ""
    ],
    [
      "Item 4",
      "Digital product Item 4",
      2500,
      17.5,
      "Replace this with the actual delivery content for Item 4.",
      ""
    ],
    [
      "Item 5",
      "Digital product Item 5",
      5000,
      35,
      "Replace this with the actual delivery content for Item 5.",
      ""
    ]
  ];

  for (const product of products) {
    insert.run(...product);
  }
}

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(express.json({
  limit: "2mb"
}));

app.use(express.urlencoded({
  extended: true,
  limit: "2mb"
}));

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "CHANGE_THIS_SESSION_SECRET",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure:
        process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

app.use(
  express.static(PUBLIC_DIR)
);

/* =========================================================
   IMAGE UPLOAD
========================================================= */

const storage = multer.diskStorage({

  destination: function(req, file, cb) {
    cb(null, PRODUCT_UPLOAD_DIR);
  },

  filename: function(req, file, cb) {

    const ext =
      path.extname(file.originalname)
        .toLowerCase();

    const safeName =
      crypto
        .randomBytes(16)
        .toString("hex");

    cb(
      null,
      `${Date.now()}-${safeName}${ext}`
    );
  }

});

const upload = multer({

  storage,

  limits: {
    fileSize: 5 * 1024 * 1024
  },

  fileFilter: function(req, file, cb) {

    if (
      !file.mimetype ||
      !file.mimetype.startsWith("image/")
    ) {
      return cb(
        new Error(
          "Only image files are allowed."
        )
      );
    }

    cb(null, true);
  }

});

/* =========================================================
   HELPERS
========================================================= */

function requireLogin(req, res, next) {

  if (!req.session.userId) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }

  next();
}

function requireAdmin(req, res, next) {

  if (!req.session.userId) {
    return res.status(401).json({
      error: "Login required."
    });
  }

  const user = db
    .prepare(
      "SELECT id, is_admin FROM users WHERE id = ?"
    )
    .get(req.session.userId);

  if (!user || !user.is_admin) {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }

  next();
}

function makeOrderNumber() {

  const random =
    crypto
      .randomBytes(4)
      .toString("hex")
      .toUpperCase();

  return `DW-${Date.now()}-${random}`;
}

function nowISO() {
  return new Date().toISOString();
}

/* =========================================================
   AUTH
========================================================= */

app.post(
  "/api/register",
  async (req, res) => {

    try {

      const {
        name,
        email,
        password
      } = req.body;

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Name, email and password are required."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            "Password must be at least 6 characters."
        });
      }

      const cleanEmail =
        email.trim().toLowerCase();

      const exists = db
        .prepare(
          "SELECT id FROM users WHERE email = ?"
        )
        .get(cleanEmail);

      if (exists) {
        return res.status(409).json({
          error:
            "An account with this email already exists."
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      const result = db
        .prepare(`
          INSERT INTO users
          (name, email, password_hash)
          VALUES (?, ?, ?)
        `)
        .run(
          name.trim(),
          cleanEmail,
          hash
        );

      req.session.userId =
        result.lastInsertRowid;

      res.json({
        success: true,
        user: {
          id: result.lastInsertRowid,
          name: name.trim(),
          email: cleanEmail,
          is_admin: false
        }
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Registration failed."
      });
    }
  }
);

app.post(
  "/api/login",
  async (req, res) => {

    try {

      const {
        email,
        password
      } = req.body;

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Email and password are required."
        });
      }

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(
          email.trim().toLowerCase()
        );

      if (!user) {
        return res.status(401).json({
          error:
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
          error:
            "Invalid email or password."
        });
      }

      req.session.userId =
        user.id;

      res.json({
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          is_admin: !!user.is_admin
        }
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Login failed."
      });
    }
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

app.get(
  "/api/me",
  (req, res) => {

    if (!req.session.userId) {
      return res.json({
        loggedIn: false
      });
    }

    const user =
      db.prepare(`
        SELECT
          id,
          name,
          email,
          is_admin
        FROM users
        WHERE id = ?
      `).get(
        req.session.userId
      );

    if (!user) {
      return res.json({
        loggedIn: false
      });
    }

    res.json({
      loggedIn: true,
      user: {
        ...user,
        is_admin: !!user.is_admin
      }
    });
  }
);

/* =========================================================
   PUBLIC PRODUCTS
========================================================= */

app.get(
  "/api/products",
  (req, res) => {

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
      products
    });
  }
);

/* =========================================================
   ADMIN PRODUCT LIST
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
      products
    });
  }
);

/* =========================================================
   ADD PRODUCT WITH IMAGE
========================================================= */

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

      if (!name) {
        return res.status(400).json({
          error: "Product name is required."
        });
      }

      const kes =
        Number(price_kes);

      const usdt =
        Number(binance_price);

      if (
        !Number.isFinite(kes) ||
        kes <= 0
      ) {
        return res.status(400).json({
          error:
            "Enter a valid KSh price."
        });
      }

      if (
        !Number.isFinite(usdt) ||
        usdt <= 0
      ) {
        return res.status(400).json({
          error:
            "Enter a valid USDT price."
        });
      }

      const imageUrl =
        req.file
          ? `/uploads/products/${req.file.filename}`
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
          name.trim(),
          (description || "").trim(),
          kes,
          usdt,
          (delivery_content || "").trim(),
          imageUrl
        );

      const product =
        db.prepare(
          "SELECT * FROM products WHERE id = ?"
        ).get(
          result.lastInsertRowid
        );

      res.json({
        success: true,
        message: "Product added successfully.",
        product
      });

    } catch (error) {

      console.error(error);

      if (req.file) {
        try {
          fs.unlinkSync(
            req.file.path
          );
        } catch (_) {}
      }

      res.status(500).json({
        error:
          "Could not add product."
      });
    }
  }
);

/* =========================================================
   UPDATE PRODUCT
========================================================= */

app.put(
  "/api/admin/products/:id",
  requireAdmin,
  upload.single("image"),
  (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const existing =
        db.prepare(
          "SELECT * FROM products WHERE id = ?"
        ).get(id);

      if (!existing) {

        if (req.file) {
          try {
            fs.unlinkSync(
              req.file.path
            );
          } catch (_) {}
        }

        return res.status(404).json({
          error: "Product not found."
        });
      }

      const {
        name,
        description,
        price_kes,
        binance_price,
        delivery_content
      } = req.body;

      const kes =
        Number(price_kes);

      const usdt =
        Number(binance_price);

      if (
        !name ||
        !Number.isFinite(kes) ||
        kes <= 0 ||
        !Number.isFinite(usdt) ||
        usdt <= 0
      ) {
        return res.status(400).json({
          error:
            "Enter valid product information."
        });
      }

      let imageUrl =
        existing.image_url || "";

      if (req.file) {

        imageUrl =
          `/uploads/products/${req.file.filename}`;

        if (
          existing.image_url &&
          existing.image_url.startsWith(
            "/uploads/products/"
          )
        ) {

          const oldPath =
            path.join(
              PUBLIC_DIR,
              existing.image_url
            );

          if (
            fs.existsSync(oldPath)
          ) {
            try {
              fs.unlinkSync(
                oldPath
              );
            } catch (_) {}
          }
        }
      }

      db.prepare(`
        UPDATE products
        SET
          name = ?,
          description = ?,
          price_kes = ?,
          binance_price = ?,
          delivery_content = ?,
          image_url = ?
        WHERE id = ?
      `).run(
        name.trim(),
        (description || "").trim(),
        kes,
        usdt,
        (delivery_content || "").trim(),
        imageUrl,
        id
      );

      const product =
        db.prepare(
          "SELECT * FROM products WHERE id = ?"
        ).get(id);

      res.json({
        success: true,
        message:
          "Product updated successfully.",
        product
      });

    } catch (error) {

      console.error(error);

      if (req.file) {
        try {
          fs.unlinkSync(
            req.file.path
          );
        } catch (_) {}
      }

      res.status(500).json({
        error:
          "Could not update product."
      });
    }
  }
);

/* =========================================================
   ACTIVATE / DEACTIVATE
========================================================= */

app.patch(
  "/api/admin/products/:id/status",
  requireAdmin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const active =
      req.body.active ? 1 : 0;

    const result =
      db.prepare(`
        UPDATE products
        SET active = ?
        WHERE id = ?
      `).run(
        active,
        id
      );

    if (!result.changes) {
      return res.status(404).json({
        error: "Product not found."
      });
    }

    res.json({
      success: true,
      active: !!active
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

    try {

      const id =
        Number(req.params.id);

      const product =
        db.prepare(
          "SELECT * FROM products WHERE id = ?"
        ).get(id);

      if (!product) {
        return res.status(404).json({
          error:
            "Product not found."
        });
      }

      const orders =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM orders
          WHERE product_id = ?
        `).get(id);

      /*
       * Keep products that already have orders.
       * Deactivate instead of deleting them.
       */
      if (orders.count > 0) {

        db.prepare(`
          UPDATE products
          SET active = 0
          WHERE id = ?
        `).run(id);

        return res.json({
          success: true,
          message:
            "Product has existing orders, so it was deactivated instead of deleted."
        });
      }

      db.prepare(
        "DELETE FROM products WHERE id = ?"
      ).run(id);

      if (
        product.image_url &&
        product.image_url.startsWith(
          "/uploads/products/"
        )
      ) {

        const imagePath =
          path.join(
            PUBLIC_DIR,
            product.image_url
          );

        if (
          fs.existsSync(imagePath)
        ) {
          try {
            fs.unlinkSync(
              imagePath
            );
          } catch (_) {}
        }
      }

      res.json({
        success: true,
        message:
          "Product deleted."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not delete product."
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

      const {
        product_id,
        payment_method,
        delivery_method,
        delivery_target,
        phone
      } = req.body;

      const product =
        db.prepare(`
          SELECT *
          FROM products
          WHERE id = ?
          AND active = 1
        `).get(
          Number(product_id)
        );

      if (!product) {
        return res.status(404).json({
          error:
            "Product not found."
        });
      }

      if (
        !["MPESA", "BINANCE"].includes(
          payment_method
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid payment method."
        });
      }

      if (
        !["EMAIL", "WHATSAPP"].includes(
          delivery_method
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid delivery method."
        });
      }

      if (
        !delivery_target ||
        delivery_target.trim().length < 3
      ) {
        return res.status(400).json({
          error:
            "Delivery target is required."
        });
      }

      const orderNumber =
        makeOrderNumber();

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
            phone,
            delivery_status
          )
          VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, 'PENDING')
        `).run(
          orderNumber,
          req.session.userId,
          product.id,
          product.price_kes,
          product.binance_price,
          payment_method,
          delivery_method,
          delivery_target.trim(),
          (phone || "").trim()
        );

      res.json({
        success: true,
        order: {
          id: result.lastInsertRowid,
          order_number: orderNumber,
          product_name: product.name,
          amount_kes: product.price_kes,
          amount_crypto:
            product.binance_price,
          payment_method,
          delivery_method,
          delivery_target
        }
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
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
        req.session.userId
      );

    res.json({
      orders
    });
  }
);

/* =========================================================
   ORDER TRACKING
========================================================= */

app.get(
  "/api/orders/:orderNumber",
  requireLogin,
  (req, res) => {

    const order =
      db.prepare(`
        SELECT
          o.*,
          p.name AS product_name,
          p.description AS product_description,
          p.image_url
        FROM orders o
        LEFT JOIN products p
          ON p.id = o.product_id
        WHERE o.order_number = ?
        AND o.user_id = ?
      `).get(
        req.params.orderNumber,
        req.session.userId
      );

    if (!order) {
      return res.status(404).json({
        error:
          "Order not found."
      });
    }

    res.json({
      order
    });
  }
);

/* =========================================================
   M-PESA ACCESS TOKEN
========================================================= */

async function getMpesaToken() {

  const consumerKey =
    process.env.MPESA_CONSUMER_KEY;

  const consumerSecret =
    process.env.MPESA_CONSUMER_SECRET;

  if (
    !consumerKey ||
    !consumerSecret
  ) {
    throw new Error(
      "M-Pesa credentials are not configured."
    );
  }

  const env =
    process.env.MPESA_ENV ===
    "production"
      ? "production"
      : "sandbox";

  const url =
    env === "production"
      ? "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
      : "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials";

  const response =
    await axios.get(
      url,
      {
        auth: {
          username: consumerKey,
          password: consumerSecret
        }
      }
    );

  return response.data.access_token;
}

/* =========================================================
   M-PESA STK PUSH
========================================================= */

app.post(
  "/api/mpesa/stkpush",
  requireLogin,
  async (req, res) => {

    try {

      const {
        order_number,
        phone
      } = req.body;

      const order =
        db.prepare(`
          SELECT *
          FROM orders
          WHERE order_number = ?
          AND user_id = ?
        `).get(
          order_number,
          req.session.userId
        );

      if (!order) {
        return res.status(404).json({
          error:
            "Order not found."
        });
      }

      if (
        order.payment_method !==
        "MPESA"
      ) {
        return res.status(400).json({
          error:
            "This order is not using M-Pesa."
        });
      }

      const shortcode =
        process.env.MPESA_SHORTCODE;

      const passkey =
        process.env.MPESA_PASSKEY;

      const callbackUrl =
        process.env.MPESA_CALLBACK_URL;

      if (
        !shortcode ||
        !passkey ||
        !callbackUrl
      ) {
        return res.status(500).json({
          error:
            "M-Pesa configuration is incomplete."
        });
      }

      const token =
        await getMpesaToken();

      const env =
        process.env.MPESA_ENV ===
        "production"
          ? "production"
          : "sandbox";

      const base =
        env === "production"
          ? "https://api.safaricom.co.ke"
          : "https://sandbox.safaricom.co.ke";

      const timestamp =
        new Date()
          .toISOString()
          .replace(
            /[-:TZ.]/g,
            ""
          )
          .slice(0, 14);

      const password =
        Buffer.from(
          shortcode +
          passkey +
          timestamp
        ).toString("base64");

      const response =
        await axios.post(
          `${base}/mpesa/stkpush/v1/processrequest`,
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
              Math.round(
                order.amount_kes
              ),

            PartyA:
              phone,

            PartyB:
              shortcode,

            PhoneNumber:
              phone,

            CallBackURL:
              callbackUrl,

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
          phone = ?
        WHERE order_number = ?
      `).run(
        response.data.CheckoutRequestID || "",
        response.data.MerchantRequestID || "",
        phone,
        order.order_number
      );

      res.json({
        success: true,
        response: response.data
      });

    } catch (error) {

      console.error(
        "M-Pesa STK error:",
        error.response?.data ||
        error.message
      );

      res.status(500).json({
        error:
          error.response?.data?.errorMessage ||
          error.message ||
          "M-Pesa STK Push failed."
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

      const callback =
        req.body?.Body?.stkCallback;

      if (!callback) {
        return res.json({
          ResultCode: 0,
          ResultDesc: "Accepted"
        });
      }

      const checkoutId =
        callback.CheckoutRequestID;

      const resultCode =
        callback.ResultCode;

      const metadata =
        callback.CallbackMetadata?.Item ||
        [];

      let receipt = "";

      for (const item of metadata) {

        if (
          item.Name ===
          "MpesaReceiptNumber"
        ) {
          receipt =
            item.Value || "";
        }
      }

      const order =
        db.prepare(`
          SELECT *
          FROM orders
          WHERE checkout_request_id = ?
        `).get(
          checkoutId
        );

      if (order) {

        if (resultCode === 0) {

          db.prepare(`
            UPDATE orders
            SET
              payment_status = 'PAID',
              delivery_status = 'PROCESSING',
              mpesa_receipt = ?,
              paid_at = ?
            WHERE id = ?
          `).run(
            receipt,
            nowISO(),
            order.id
          );

        } else {

          db.prepare(`
            UPDATE orders
            SET payment_status = 'PAYMENT_FAILED'
            WHERE id = ?
          `).run(
            order.id
          );
        }
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
   BINANCE PAYMENT INFORMATION
========================================================= */

app.get(
  "/api/binance/payment-info",
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
        "Send the exact amount, then submit your transaction hash for manual verification."
    });
  }
);

/* =========================================================
   BINANCE TXID SUBMISSION
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

      if (
        !order_number ||
        !txid
      ) {
        return res.status(400).json({
          error:
            "Order number and transaction hash are required."
        });
      }

      const order =
        db.prepare(`
          SELECT *
          FROM orders
          WHERE order_number = ?
          AND user_id = ?
        `).get(
          order_number,
          req.session.userId
        );

      if (!order) {
        return res.status(404).json({
          error:
            "Order not found."
        });
      }

      db.prepare(`
        UPDATE orders
        SET
          binance_txid = ?,
          payment_status = 'PAYMENT_REVIEW'
        WHERE id = ?
      `).run(
        txid.trim(),
        order.id
      );

      res.json({
        success: true,
        message:
          "Transaction submitted for manual verification."
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

    const orders =
      db.prepare(`
        SELECT
          o.*,
          p.name AS product_name,
          u.name AS customer_name,
          u.email AS customer_email
        FROM orders o
        LEFT JOIN products p
          ON p.id = o.product_id
        LEFT JOIN users u
          ON u.id = o.user_id
        ORDER BY o.id DESC
      `).all();

    res.json({
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

    const id =
      Number(req.params.id);

    const {
      approved
    } = req.body;

    const order =
      db.prepare(
        "SELECT * FROM orders WHERE id = ?"
      ).get(id);

    if (!order) {
      return res.status(404).json({
        error:
          "Order not found."
      });
    }

    if (approved) {

      db.prepare(`
        UPDATE orders
        SET
          payment_status = 'PAID',
          binance_verified = 1,
          delivery_status = 'PROCESSING',
          paid_at = ?
        WHERE id = ?
      `).run(
        nowISO(),
        id
      );

    } else {

      db.prepare(`
        UPDATE orders
        SET
          payment_status = 'PAYMENT_FAILED',
          binance_verified = 0
        WHERE id = ?
      `).run(
        id
      );
    }

    res.json({
      success: true
    });
  }
);

/* =========================================================
   ADMIN DELIVERY STATUS
========================================================= */

app.post(
  "/api/admin/orders/:id/delivery",
  requireAdmin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const {
      status,
      notes
    } = req.body;

    const allowed = [
      "PENDING",
      "PROCESSING",
      "DELIVERING",
      "DELIVERED"
    ];

    if (
      !allowed.includes(status)
    ) {
      return res.status(400).json({
        error:
          "Invalid delivery status."
      });
    }

    const deliveredAt =
      status === "DELIVERED"
        ? nowISO()
        : "";

    const result =
      db.prepare(`
        UPDATE orders
        SET
          delivery_status = ?,
          delivery_notes = ?,
          delivered_at = ?
        WHERE id = ?
      `).run(
        status,
        notes || "",
        deliveredAt,
        id
      );

    if (!result.changes) {
      return res.status(404).json({
        error:
          "Order not found."
      });
    }

    res.json({
      success: true
    });
  }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/api/health",
  (req, res) => {

    res.json({
      ok: true,
      service:
        "DARK WEB Store",
      time:
        new Date().toISOString()
    });
  }
);

/* =========================================================
   MULTER ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {

    if (
      error instanceof multer.MulterError
    ) {

      if (
        error.code ===
        "LIMIT_FILE_SIZE"
      ) {
        return res.status(400).json({
          error:
            "Image is too large. Maximum size is 5MB."
        });
      }

      return res.status(400).json({
        error:
          error.message
      });
    }

    if (
      error &&
      error.message ===
      "Only image files are allowed."
    ) {
      return res.status(400).json({
        error:
          "Only image files are allowed."
      });
    }

    next(error);
  }
);

/* =========================================================
   START
========================================================= */

app.listen(
  PORT,
  () => {

    console.log(
      `DARK WEB Store running on port ${PORT}`
    );

    console.log(
      `http://localhost:${PORT}`
    );

  }
);
