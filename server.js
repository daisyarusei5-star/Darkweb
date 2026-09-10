"use strict";

/*
=========================================================
 DARK WEB — DIGITAL STORE
 FULL SERVER.JS
 MATCHED TO THE PROVIDED INDEX.HTML
=========================================================

Required packages:

npm install express better-sqlite3 express-session bcryptjs
npm install multer axios

Environment variables:

NODE_ENV=production
PORT=10000

BASE_URL=https://YOUR-RENDER-SERVICE.onrender.com
SESSION_SECRET=CHANGE_THIS_TO_A_LONG_RANDOM_SECRET

ADMIN_EMAIL=your-admin-email@example.com
ADMIN_PASSWORD=your-admin-password

PAYSTACK_SECRET_KEY=sk_test_xxxxxxxxx
PAYSTACK_CURRENCY=KES
PAYSTACK_CHANNELS=mobile_money,card

BINANCE_PAY_CERTIFICATE_SN=YOUR_BINANCE_API_KEY
BINANCE_PAY_SECRET_KEY=YOUR_BINANCE_SECRET_KEY
BINANCE_CURRENCY=USDT

BINANCE_CREATE_PATH=/binancepay/openapi/order
BINANCE_QUERY_PATH=/binancepay/openapi/order/query

SUPPORT_WHATSAPP=254781601410

DB_PATH=./darkweb.db
=========================================================
*/


/* =========================================================
   IMPORTS
========================================================= */

const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");


/* =========================================================
   APP
========================================================= */

const app = express();

const PORT =
  Number(process.env.PORT || 10000);

const NODE_ENV =
  process.env.NODE_ENV || "development";

const BASE_URL =
  String(
    process.env.BASE_URL ||
    ""
  ).replace(/\/+$/, "");

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "CHANGE_ME_SESSION_SECRET";

const ADMIN_EMAIL =
  String(
    process.env.ADMIN_EMAIL ||
    ""
  ).trim()
  .toLowerCase();

const ADMIN_PASSWORD =
  String(
    process.env.ADMIN_PASSWORD ||
    ""
  );

const SUPPORT_WHATSAPP =
  String(
    process.env.SUPPORT_WHATSAPP ||
    "254781601410"
  );


/* =========================================================
   PAYMENT CONFIG
========================================================= */

const PAYSTACK_SECRET_KEY =
  String(
    process.env.PAYSTACK_SECRET_KEY ||
    ""
  ).trim();

const PAYSTACK_CURRENCY =
  String(
    process.env.PAYSTACK_CURRENCY ||
    "KES"
  ).toUpperCase();

const PAYSTACK_CHANNELS =
  String(
    process.env.PAYSTACK_CHANNELS ||
    "mobile_money,card"
  )
  .split(",")
  .map(x => x.trim())
  .filter(Boolean);


const BINANCE_CERTIFICATE_SN =
  String(
    process.env.BINANCE_PAY_CERTIFICATE_SN ||
    ""
  ).trim();

const BINANCE_SECRET_KEY =
  String(
    process.env.BINANCE_PAY_SECRET_KEY ||
    ""
  ).trim();

const BINANCE_CURRENCY =
  String(
    process.env.BINANCE_CURRENCY ||
    "USDT"
  ).toUpperCase();

const BINANCE_CREATE_PATH =
  process.env.BINANCE_CREATE_PATH ||
  "/binancepay/openapi/order";

const BINANCE_QUERY_PATH =
  process.env.BINANCE_QUERY_PATH ||
  "/binancepay/openapi/order/query";


/* =========================================================
   PATHS
========================================================= */

const ROOT_DIR =
  __dirname;

const PUBLIC_DIR =
  path.join(
    ROOT_DIR,
    "public"
  );

const UPLOAD_DIR =
  path.join(
    PUBLIC_DIR,
    "uploads",
    "products"
  );

const DB_PATH =
  process.env.DB_PATH ||
  path.join(
    ROOT_DIR,
    "darkweb.db"
  );


/* =========================================================
   CREATE DIRECTORIES
========================================================= */

fs.mkdirSync(
  PUBLIC_DIR,
  {
    recursive:true
  }
);

fs.mkdirSync(
  UPLOAD_DIR,
  {
    recursive:true
  }
);


/* =========================================================
   DATABASE
========================================================= */

const db =
  new Database(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");


/* =========================================================
   DATABASE TABLES
========================================================= */

db.exec(`
  CREATE TABLE IF NOT EXISTS users (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    name TEXT NOT NULL,

    email TEXT NOT NULL UNIQUE,

    password_hash TEXT NOT NULL,

    is_admin INTEGER NOT NULL DEFAULT 0,

    created_at TEXT NOT NULL
      DEFAULT CURRENT_TIMESTAMP

  );


  CREATE TABLE IF NOT EXISTS products (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    name TEXT NOT NULL,

    description TEXT NOT NULL DEFAULT '',

    price_kes REAL NOT NULL DEFAULT 0,

    binance_price REAL NOT NULL DEFAULT 0,

    delivery_content TEXT NOT NULL DEFAULT '',

    image_url TEXT NOT NULL DEFAULT '',

    active INTEGER NOT NULL DEFAULT 1,

    created_at TEXT NOT NULL
      DEFAULT CURRENT_TIMESTAMP

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

    delivery_method TEXT NOT NULL,

    delivery_target TEXT NOT NULL,

    phone TEXT NOT NULL DEFAULT '',

    checkout_request_id TEXT,

    merchant_request_id TEXT,

    mpesa_receipt TEXT,

    paystack_reference TEXT,

    paystack_transaction_id TEXT,

    paystack_receipt TEXT,

    binance_merchant_trade_no TEXT,

    binance_prepay_id TEXT,

    binance_transaction_id TEXT,

    binance_verified INTEGER NOT NULL DEFAULT 0,

    binance_txid TEXT,

    delivery_status TEXT NOT NULL DEFAULT 'pending',

    delivery_notes TEXT NOT NULL DEFAULT '',

    created_at TEXT NOT NULL
      DEFAULT CURRENT_TIMESTAMP,

    paid_at TEXT,

    delivered_at TEXT,

    FOREIGN KEY(user_id)
      REFERENCES users(id)
      ON DELETE CASCADE,

    FOREIGN KEY(product_id)
      REFERENCES products(id)
      ON DELETE RESTRICT

  );

  CREATE INDEX IF NOT EXISTS
    idx_orders_user
    ON orders(user_id);

  CREATE INDEX IF NOT EXISTS
    idx_orders_number
    ON orders(order_number);

  CREATE INDEX IF NOT EXISTS
    idx_orders_status
    ON orders(payment_status);

  CREATE INDEX IF NOT EXISTS
    idx_orders_binance
    ON orders(binance_merchant_trade_no);
`);


/* =========================================================
   CREATE ADMIN
========================================================= */

if(
  ADMIN_EMAIL &&
  ADMIN_PASSWORD
){

  const existingAdmin =
    db.prepare(`
      SELECT id
      FROM users
      WHERE email = ?
    `).get(
      ADMIN_EMAIL
    );

  if(!existingAdmin){

    const passwordHash =
      bcrypt.hashSync(
        ADMIN_PASSWORD,
        12
      );

    db.prepare(`
      INSERT INTO users
      (
        name,
        email,
        password_hash,
        is_admin
      )
      VALUES
      (?, ?, ?, 1)
    `).run(
      "Administrator",
      ADMIN_EMAIL,
      passwordHash
    );

    console.log(
      "ADMIN ACCOUNT CREATED:",
      ADMIN_EMAIL
    );

  }else{

    db.prepare(`
      UPDATE users
      SET is_admin = 1
      WHERE email = ?
    `).run(
      ADMIN_EMAIL
    );

  }

}


/* =========================================================
   MIDDLEWARE
========================================================= */

app.set(
  "trust proxy",
  1
);

app.use(
  express.json({
    limit:"2mb"
  })
);

app.use(
  express.urlencoded({
    extended:true,
    limit:"2mb"
  })
);


/* =========================================================
   SESSION
========================================================= */

app.use(
  session({

    secret:
      SESSION_SECRET,

    resave:false,

    saveUninitialized:false,

    cookie:{

      httpOnly:true,

      secure:
        NODE_ENV === "production",

      sameSite:"lax",

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
  express.static(
    PUBLIC_DIR
  )
);


/* =========================================================
   MULTER
========================================================= */

const storage =
  multer.diskStorage({

    destination:
      function(
        req,
        file,
        cb
      ){

        cb(
          null,
          UPLOAD_DIR
        );

      },

    filename:
      function(
        req,
        file,
        cb
      ){

        const ext =
          path.extname(
            file.originalname
          ).toLowerCase();

        const safeExt =
          [
            ".jpg",
            ".jpeg",
            ".png",
            ".webp",
            ".gif"
          ].includes(ext)
            ? ext
            : ".jpg";

        const filename =
          "product-" +
          Date.now() +
          "-" +
          crypto
            .randomBytes(5)
            .toString("hex") +
          safeExt;

        cb(
          null,
          filename
        );

      }

  });


const upload =
  multer({

    storage,

    limits:{
      fileSize:
        5 * 1024 * 1024
    },

    fileFilter:
      function(
        req,
        file,
        cb
      ){

        if(
          file.mimetype &&
          file.mimetype.startsWith(
            "image/"
          )
        ){

          cb(
            null,
            true
          );

        }else{

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

function cleanText(value){

  return String(
    value ??
    ""
  ).trim();

}


function money(value){

  const number =
    Number(
      value
    );

  if(
    !Number.isFinite(number)
  ){

    return 0;

  }

  return Math.round(
    number * 100
  ) / 100;

}


function normalizeEmail(email){

  return cleanText(
    email
  ).toLowerCase();

}


function generateOrderNumber(){

  let number;

  do{

    number =
      "DW" +
      Date.now().toString(36).toUpperCase() +
      crypto
        .randomBytes(4)
        .toString("hex")
        .toUpperCase();

  }while(
    db.prepare(`
      SELECT id
      FROM orders
      WHERE order_number = ?
    `).get(number)
  );

  return number;

}


function now(){

  return new Date()
    .toISOString();

}


function userPublic(user){

  if(!user){
    return null;
  }

  return {

    id:
      user.id,

    name:
      user.name,

    email:
      user.email,

    is_admin:
      Number(user.is_admin) === 1

  };

}


function requireLogin(
  req,
  res,
  next
){

  if(
    !req.session.userId
  ){

    return res.status(401).json({

      success:false,

      message:
        "Please login first."

    });

  }

  next();

}


function requireAdmin(
  req,
  res,
  next
){

  if(
    !req.session.userId
  ){

    return res.status(401).json({

      success:false,

      message:
        "Please login first."

    });

  }

  const user =
    db.prepare(`
      SELECT *
      FROM users
      WHERE id = ?
    `).get(
      req.session.userId
    );

  if(
    !user ||
    Number(user.is_admin) !== 1
  ){

    return res.status(403).json({

      success:false,

      message:
        "Admin access required."

    });

  }

  req.currentUser =
    user;

  next();

}


function publicProduct(
  product
){

  return {

    id:
      product.id,

    name:
      product.name,

    description:
      product.description,

    price_kes:
      money(product.price_kes),

    binance_price:
      money(product.binance_price),

    image_url:
      product.image_url || "",

    active:
      Number(product.active) === 1,

    created_at:
      product.created_at

  };

}


function orderForUser(
  order
){

  return {

    id:
      order.id,

    order_number:
      order.order_number,

    product_id:
      order.product_id,

    product_name:
      order.product_name,

    amount_kes:
      money(order.amount_kes),

    amount_crypto:
      money(order.amount_crypto),

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
      order.delivered_at,

    delivery_content:
      (
        order.payment_status === "paid" &&
        order.delivery_status === "delivered"
      )
      ?
      order.delivery_content
      :
      null

  };

}


function getOrderByNumber(
  orderNumber
){

  return db.prepare(`
    SELECT
      o.*,

      p.name AS product_name,

      p.description AS product_description,

      p.delivery_content,

      p.image_url,

      u.name AS user_name,

      u.email AS user_email

    FROM orders o

    LEFT JOIN products p
      ON p.id = o.product_id

    LEFT JOIN users u
      ON u.id = o.user_id

    WHERE o.order_number = ?

  `).get(
    orderNumber
  );

}


function getBaseUrl(
  req
){

  if(BASE_URL){
    return BASE_URL;
  }

  const protocol =
    req.headers["x-forwarded-proto"] ||
    req.protocol;

  const host =
    req.get("host");

  return `${protocol}://${host}`;

}


/* =========================================================
   AUTH
========================================================= */

app.post(
  "/api/register",
  async function(
    req,
    res
  ){

    try{

      const name =
        cleanText(
          req.body.name
        );

      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        String(
          req.body.password ||
          ""
        );

      if(!name){

        return res.status(400).json({

          success:false,

          message:
            "Name is required."

        });

      }

      if(!email){

        return res.status(400).json({

          success:false,

          message:
            "Email is required."

        });

      }

      if(password.length < 6){

        return res.status(400).json({

          success:false,

          message:
            "Password must be at least 6 characters."

        });

      }

      const existing =
        db.prepare(`
          SELECT id
          FROM users
          WHERE email = ?
        `).get(
          email
        );

      if(existing){

        return res.status(409).json({

          success:false,

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
          (
            name,
            email,
            password_hash
          )
          VALUES
          (?, ?, ?)
        `).run(
          name,
          email,
          hash
        );

      req.session.userId =
        Number(
          result.lastInsertRowid
        );

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE id = ?
        `).get(
          req.session.userId
        );

      res.json({

        success:true,

        user:
          userPublic(user)

      });

    }catch(error){

      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({

        success:false,

        message:
          "Unable to create account."

      });

    }

  }
);


/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  async function(
    req,
    res
  ){

    try{

      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        String(
          req.body.password ||
          ""
        );

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(
          email
        );

      if(
        !user ||
        !(await bcrypt.compare(
          password,
          user.password_hash
        ))
      ){

        return res.status(401).json({

          success:false,

          message:
            "Invalid email or password."

        });

      }

      req.session.userId =
        user.id;

      res.json({

        success:true,

        user:
          userPublic(user)

      });

    }catch(error){

      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({

        success:false,

        message:
          "Unable to login."

      });

    }

  }
);


/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/me",
  function(
    req,
    res
  ){

    if(
      !req.session.userId
    ){

      return res.json({

        success:true,

        user:null

      });

    }

    const user =
      db.prepare(`
        SELECT *
        FROM users
        WHERE id = ?
      `).get(
        req.session.userId
      );

    if(!user){

      req.session.destroy(
        () => {}
      );

      return res.json({

        success:true,

        user:null

      });

    }

    res.json({

      success:true,

      user:
        userPublic(user)

    });

  }
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/logout",
  function(
    req,
    res
  ){

    req.session.destroy(
      function(){

        res.json({

          success:true,

          message:
            "Logged out."

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
  function(
    req,
    res
  ){

    try{

      const products =
        db.prepare(`
          SELECT *
          FROM products
          WHERE active = 1
          ORDER BY id DESC
        `).all();

      res.json({

        success:true,

        products:
          products.map(
            publicProduct
          )

      });

    }catch(error){

      console.error(
        "PRODUCT ERROR:",
        error
      );

      res.status(500).json({

        success:false,

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
  function(
    req,
    res
  ){

    try{

      const products =
        db.prepare(`
          SELECT *
          FROM products
          ORDER BY id DESC
        `).all();

      res.json({

        success:true,

        products:
          products.map(
            publicProduct
          )

      });

    }catch(error){

      console.error(
        "ADMIN PRODUCT ERROR:",
        error
      );

      res.status(500).json({

        success:false,

        message:
          "Unable to load admin products."

      });

    }

  }
);


/* =========================================================
   ADD PRODUCT
========================================================= */

app.post(
  "/api/admin/products",
  requireAdmin,
  upload.single("image"),
  function(
    req,
    res
  ){

    try{

      const name =
        cleanText(
          req.body.name
        );

      const description =
        cleanText(
          req.body.description
        );

      /*
       * EXACT NAMES USED BY YOUR HTML
       */
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

      if(!name){

        return res.status(400).json({

          success:false,

          message:
            "Product name is required."

        });

      }

      if(
        priceKes <= 0 &&
        binancePrice <= 0
      ){

        return res.status(400).json({

          success:false,

          message:
            "Set a valid KSh or Binance price."

        });

      }

      if(
        priceKes < 0 ||
        binancePrice < 0
      ){

        return res.status(400).json({

          success:false,

          message:
            "Prices cannot be negative."

        });

      }

      if(!description){

        return res.status(400).json({

          success:false,

          message:
            "Product description is required."

        });

      }

      if(!deliveryContent){

        return res.status(400).json({

          success:false,

          message:
            "Delivery content is required."

        });

      }

      let imageUrl = "";

      if(req.file){

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

      res.json({

        success:true,

        message:
          "Product added successfully.",

        product:
          publicProduct(product)

      });

    }catch(error){

      console.error(
        "ADD PRODUCT ERROR:",
        error
      );

      if(req.file){

        try{

          fs.unlinkSync(
            req.file.path
          );

        }catch(e){}

      }

      res.status(500).json({

        success:false,

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
  function(
    req,
    res
  ){

    try{

      const id =
        Number(
          req.params.id
        );

      const product =
        db.prepare(`
          SELECT *
          FROM products
          WHERE id = ?
        `).get(
          id
        );

      if(!product){

        return res.status(404).json({

          success:false,

          message:
            "Product not found."

        });

      }

      const newStatus =
        Number(product.active) === 1
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

      res.json({

        success:true,

        message:
          newStatus
            ? "Product enabled."
            : "Product disabled."

      });

    }catch(error){

      console.error(
        "TOGGLE PRODUCT ERROR:",
        error
      );

      res.status(500).json({

        success:false,

        message:
          "Unable to update product."

      });

    }

  }
);


/* =========================================================
   DELETE PRODUCT
========================================================= */

app.delete(
  "/api/admin/products/:id",
  requireAdmin,
  function(
    req,
    res
  ){

    try{

      const id =
        Number(
          req.params.id
        );

      const product =
        db.prepare(`
          SELECT *
          FROM products
          WHERE id = ?
        `).get(
          id
        );

      if(!product){

        return res.status(404).json({

          success:false,

          message:
            "Product not found."

        });

      }

      const order =
        db.prepare(`
          SELECT id
          FROM orders
          WHERE product_id = ?
          LIMIT 1
        `).get(
          id
        );

      if(order){

        return res.status(409).json({

          success:false,

          message:
            "This product has orders and cannot be deleted. Disable it instead."

        });

      }

      db.prepare(`
        DELETE FROM products
        WHERE id = ?
      `).run(
        id
      );

      if(product.image_url){

        const filename =
          path.basename(
            product.image_url
          );

        const imagePath =
          path.join(
            UPLOAD_DIR,
            filename
          );

        try{

          if(
            fs.existsSync(
              imagePath
            )
          ){

            fs.unlinkSync(
              imagePath
            );

          }

        }catch(e){}

      }

      res.json({

        success:true,

        message:
          "Product deleted."

      });

    }catch(error){

      console.error(
        "DELETE PRODUCT ERROR:",
        error
      );

      res.status(500).json({

        success:false,

        message:
          "Unable to delete product."

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
  function(
    req,
    res
  ){

    try{

      /*
       * YOUR HTML SENDS:
       *
       * productId
       * paymentMethod
       * deliveryMethod
       * deliveryTarget
       * phone
       */

      const productId =
        Number(
          req.body.productId
        );

      const paymentMethod =
        cleanText(
          req.body.paymentMethod
        ).toLowerCase();

      const deliveryMethod =
        cleanText(
          req.body.deliveryMethod
        ).toLowerCase();

      const deliveryTarget =
        cleanText(
          req.body.deliveryTarget
        );

      const phone =
        cleanText(
          req.body.phone
        );


      if(
        !Number.isInteger(
          productId
        ) ||
        productId <= 0
      ){

        return res.status(400).json({

          success:false,

          message:
            "Invalid product."

        });

      }


      if(
        ![
          "paystack",
          "binance"
        ].includes(
          paymentMethod
        )
      ){

        return res.status(400).json({

          success:false,

          message:
            "Unsupported payment method."

        });

      }


      if(
        ![
          "email",
          "whatsapp"
        ].includes(
          deliveryMethod
        )
      ){

        return res.status(400).json({

          success:false,

          message:
            "Invalid delivery method."

        });

      }


      if(!deliveryTarget){

        return res.status(400).json({

          success:false,

          message:
            "Delivery contact is required."

        });

      }


      if(!phone){

        return res.status(400).json({

          success:false,

          message:
            "Phone / WhatsApp number is required."

        });

      }


      const product =
        db.prepare(`
          SELECT *
          FROM products
          WHERE id = ?
          AND active = 1
        `).get(
          productId
        );


      if(!product){

        return res.status(404).json({

          success:false,

          message:
            "Product is unavailable."

        });

      }


      const priceKes =
        money(
          product.price_kes
        );

      const binancePrice =
        money(
          product.binance_price
        );


      if(
        paymentMethod === "paystack" &&
        priceKes <= 0
      ){

        return res.status(400).json({

          success:false,

          message:
            "Paystack is not available for this product."

        });

      }


      if(
        paymentMethod === "binance" &&
        binancePrice <= 0
      ){

        return res.status(400).json({

          success:false,

          message:
            "Binance Pay is not available for this product."

        });

      }


      const orderNumber =
        generateOrderNumber();


      const amountKes =
        paymentMethod === "paystack"
          ? priceKes
          : 0;


      const amountCrypto =
        paymentMethod === "binance"
          ? binancePrice
          : 0;


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
          VALUES
          (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
        `).run(

          orderNumber,

          req.session.userId,

          productId,

          amountKes,

          amountCrypto,

          paymentMethod,

          deliveryMethod,

          deliveryTarget,

          phone

        );


      const order =
        getOrderByNumber(
          orderNumber
        );


      res.json({

        success:true,

        message:
          "Order created.",

        order:{

          id:
            result.lastInsertRowid,

          order_number:
            order.order_number,

          product_name:
            order.product_name,

          amount_kes:
            order.amount_kes,

          amount_crypto:
            order.amount_crypto,

          payment_method:
            order.payment_method,

          payment_status:
            order.payment_status

        }

      });

    }catch(error){

      console.error(
        "CREATE ORDER ERROR:",
        error
      );

      res.status(500).json({

        success:false,

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
  function(
    req,
    res
  ){

    try{

      const orders =
        db.prepare(`
          SELECT

            o.*,

            p.name AS product_name,

            p.delivery_content

          FROM orders o

          LEFT JOIN products p
            ON p.id = o.product_id

          WHERE o.user_id = ?

          ORDER BY o.id DESC

        `).all(
          req.session.userId
        );


      res.json({

        success:true,

        orders:
          orders.map(
            orderForUser
          )

      });

    }catch(error){

      console.error(
        "USER ORDERS ERROR:",
        error
      );

      res.status(500).json({

        success:false,

        message:
          "Unable to load orders."

      });

    }

  }
);


/* =========================================================
   VIEW SINGLE ORDER
========================================================= */

app.get(
  "/api/orders/:orderNumber",
  requireLogin,
  function(
    req,
    res
  ){

    try{

      const orderNumber =
        cleanText(
          req.params.orderNumber
        );

      const order =
        getOrderByNumber(
          orderNumber
        );

      if(!order){

        return res.status(404).json({

          success:false,

          message:
            "Order not found."

        });

      }

      if(
        Number(order.user_id) !==
        Number(req.session.userId)
      ){

        return res.status(403).json({

          success:false,

          message:
            "You cannot view this order."

        });

      }


      res.json({

        success:true,

        order:
          orderForUser(order)

      });

    }catch(error){

      console.error(
        "VIEW ORDER ERROR:",
        error
      );

      res.status(500).json({

        success:false,

        message:
          "Unable to load order."

      });

    }

  }
);


/* =========================================================
   PAYSTACK INIT
========================================================= */

app.post(
  "/api/paystack/init",
  requireLogin,
  async function(
    req,
    res
  ){

    try{

      if(
        !PAYSTACK_SECRET_KEY
      ){

        return res.status(503).json({

          success:false,

          message:
            "Paystack is not configured."

        });

      }


      const orderNumber =
        cleanText(
          req.body.orderNumber
        );


      if(!orderNumber){

        return res.status(400).json({

          success:false,

          message:
            "Order number is required."

        });

      }


      const order =
        getOrderByNumber(
          orderNumber
        );


      if(!order){

        return res.status(404).json({

          success:false,

          message:
            "Order not found."

        });

      }


      if(
        Number(order.user_id) !==
        Number(req.session.userId)
      ){

        return res.status(403).json({

          success:false,

          message:
            "You cannot pay for this order."

        });

      }


      if(
        order.payment_method !==
        "paystack"
      ){

        return res.status(400).json({

          success:false,

          message:
            "This order is not a Paystack order."

        });

      }


      if(
        order.payment_status ===
        "paid"
      ){

        return res.json({

          success:true,

          message:
            "Order is already paid.",

          paid:true,

          reference:
            order.paystack_reference ||
            order.order_number

        });

      }


      if(
        money(order.amount_kes) <= 0
      ){

        return res.status(400).json({

          success:false,

          message:
            "Invalid KSh order amount."

        });

      }


      const reference =
        order.paystack_reference ||
        order.order_number;


      const callbackUrl =
        getBaseUrl(req) +
        "/?payment=paystack&reference=" +
        encodeURIComponent(
          reference
        );


      const body = {

        email:
          order.user_email,

        amount:
          Math.round(
            Number(
              order.amount_kes
            ) * 100
          ),

        currency:
          PAYSTACK_CURRENCY,

        reference,

        callback_url:
          callbackUrl,

        channels:
          PAYSTACK_CHANNELS,

        metadata:{

          order_number:
            order.order_number,

          user_id:
            order.user_id,

          product_id:
            order.product_id

        }

      };


      const response =
        await axios.post(

          "https://api.paystack.co/transaction/initialize",

          body,

          {

            headers:{

              Authorization:
                `Bearer ${PAYSTACK_SECRET_KEY}`,

              "Content-Type":
                "application/json"

            },

            timeout:
              20000

          }

        );


      const data =
        response.data;


      if(
        !data ||
        !data.status ||
        !data.data
      ){

        throw new Error(
          data?.message ||
          "Paystack initialization failed."
        );

      }


      db.prepare(`
        UPDATE orders

        SET
          paystack_reference = ?

        WHERE
          order_number = ?
      `).run(

        reference,

        orderNumber

      );


      res.json({

        success:true,

        authorization_url:
          data.data.authorization_url,

        access_code:
          data.data.access_code,

        reference:
          data.data.reference

      });

    }catch(error){

      console.error(
        "PAYSTACK INIT ERROR:",
        error.response?.data ||
        error
      );

      res.status(500).json({

        success:false,

        message:
          error.response?.data?.message ||
          error.message ||
          "Unable to initialize Paystack."

      });

    }

  }
);


/* =========================================================
   PAYSTACK VERIFY
========================================================= */

app.get(
  "/api/paystack/verify/:reference",
  requireLogin,
  async function(
    req,
    res
  ){

    try{

      if(
        !PAYSTACK_SECRET_KEY
      ){

        return res.status(503).json({

          success:false,

          message:
            "Paystack is not configured."

        });

      }


      const reference =
        cleanText(
          req.params.reference
        );


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


      if(!order){

        return res.status(404).json({

          success:false,

          message:
            "Order not found."

        });

      }


      if(
        Number(order.user_id) !==
        Number(req.session.userId)
      ){

        return res.status(403).json({

          success:false,

          message:
            "You cannot verify this order."

        });

      }


      const response =
        await axios.get(

          "https://api.paystack.co/transaction/verify/" +
          encodeURIComponent(
            reference
          ),

          {

            headers:{

              Authorization:
                `Bearer ${PAYSTACK_SECRET_KEY}`

            },

            timeout:
              20000

          }

        );


      const data =
        response.data;


      const transaction =
        data?.data;


      const paid =
        Boolean(
          data?.status &&
          transaction?.status ===
            "success"
        );


      const exactAmount =
        Number(
          transaction?.amount
        ) ===
        Math.round(
          Number(
            order.amount_kes
          ) * 100
        );


      const exactCurrency =
        String(
          transaction?.currency ||
          ""
        ).toUpperCase() ===
        PAYSTACK_CURRENCY;


      const exactReference =
        String(
          transaction?.reference ||
          ""
        ) ===
        String(
          order.paystack_reference ||
          order.order_number
        );


      const confirmed =
        paid &&
        exactAmount &&
        exactCurrency &&
        exactReference;


      if(confirmed){

        db.prepare(`
          UPDATE orders

          SET

            payment_status = 'paid',

            paystack_reference = ?,

            paystack_transaction_id = ?,

            paystack_receipt = ?,

            paid_at =
              COALESCE(
                paid_at,
                ?
              )

          WHERE
            id = ?

        `).run(

          transaction.reference ||
            reference,

          transaction.id
            ? String(transaction.id)
            : "",

          transaction.receipt_number
            ? String(
                transaction.receipt_number
              )
            : "",

          now(),

          order.id

        );

      }


      res.json({

        success:true,

        paid:
          confirmed,

        orderNumber:
          order.order_number,

        message:
          confirmed
            ? "Payment confirmed."
            : "Payment is not confirmed."

      });

    }catch(error){

      console.error(
        "PAYSTACK VERIFY ERROR:",
        error.response?.data ||
        error
      );

      res.status(500).json({

        success:false,

        paid:false,

        message:
          error.response?.data?.message ||
          error.message ||
          "Unable to verify Paystack payment."

      });

    }

  }
);


/* =========================================================
   PAYSTACK WEBHOOK
========================================================= */

app.post(
  "/api/paystack/webhook",
  function(
    req,
    res
  ){

    try{

      const signature =
        req.headers[
          "x-paystack-signature"
        ];

      if(!signature){

        return res.status(401).send(
          "Missing signature"
        );

      }


      const rawBody =
        JSON.stringify(
          req.body
        );


      const expected =
        crypto
          .createHmac(
            "sha512",
            PAYSTACK_SECRET_KEY
          )
          .update(
            rawBody
          )
          .digest("hex");


      if(
        !crypto.timingSafeEqual(
          Buffer.from(
            expected
          ),
          Buffer.from(
            String(signature)
          )
        )
      ){

        return res.status(401).send(
          "Invalid signature"
        );

      }


      const event =
        req.body;


      if(
        event &&
        event.event ===
          "charge.success"
      ){

        const transaction =
          event.data;


        const reference =
          transaction?.reference;


        if(reference){

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


          if(order){

            const exactAmount =
              Number(
                transaction.amount
              ) ===
              Math.round(
                Number(
                  order.amount_kes
                ) * 100
              );


            const exactCurrency =
              String(
                transaction.currency ||
                ""
              ).toUpperCase() ===
              PAYSTACK_CURRENCY;


            if(
              exactAmount &&
              exactCurrency
            ){

              db.prepare(`
                UPDATE orders

                SET

                  payment_status =
                    'paid',

                  paystack_reference =
                    ?,

                  paystack_transaction_id =
                    ?,

                  paystack_receipt =
                    ?,

                  paid_at =
                    COALESCE(
                      paid_at,
                      ?
                    )

                WHERE
                  id = ?

              `).run(

                reference,

                transaction.id
                  ? String(transaction.id)
                  : "",

                transaction.receipt_number
                  ? String(
                      transaction.receipt_number
                    )
                  : "",

                now(),

                order.id

              );

            }

          }

        }

      }


      res.sendStatus(200);

    }catch(error){

      console.error(
        "PAYSTACK WEBHOOK ERROR:",
        error
      );

      res.sendStatus(200);

    }

  }
);


/* =========================================================
   BINANCE SIGNATURE
========================================================= */

function binanceSignature(
  timestamp,
  nonce,
  body
){

  const payload =
    `${timestamp}\n${nonce}\n${body}\n`;

  return crypto
    .createHmac(
      "sha512",
      BINANCE_SECRET_KEY
    )
    .update(
      payload
    )
    .digest("hex")
    .toUpperCase();

}


/* =========================================================
   BINANCE REQUEST
========================================================= */

async function binanceRequest(
  apiPath,
  bodyObject
){

  if(
    !BINANCE_CERTIFICATE_SN ||
    !BINANCE_SECRET_KEY
  ){

    throw new Error(
      "Binance Pay is not configured."
    );

  }


  const timestamp =
    String(
      Date.now()
    );

  const nonce =
    crypto
      .randomBytes(16)
      .toString("hex")
      .slice(
        0,
        32
      );


  const body =
    JSON.stringify(
      bodyObject
    );


  const signature =
    binanceSignature(
      timestamp,
      nonce,
      body
    );


  const response =
    await axios.post(

      "https://bpay.binanceapi.com" +
      apiPath,

      body,

      {

        headers:{

          "Content-Type":
            "application/json",

          "BinancePay-Timestamp":
            timestamp,

          "BinancePay-Nonce":
            nonce,

          "BinancePay-Certificate-SN":
            BINANCE_CERTIFICATE_SN,

          "BinancePay-Signature":
            signature

        },

        timeout:
          20000

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
  async function(
    req,
    res
  ){

    try{

      if(
        !BINANCE_CERTIFICATE_SN ||
        !BINANCE_SECRET_KEY
      ){

        return res.status(503).json({

          success:false,

          message:
            "Binance Pay is not configured."

        });

      }


      const orderNumber =
        cleanText(
          req.body.orderNumber
        );


      if(!orderNumber){

        return res.status(400).json({

          success:false,

          message:
            "Order number is required."

        });

      }


      const order =
        getOrderByNumber(
          orderNumber
        );


      if(!order){

        return res.status(404).json({

          success:false,

          message:
            "Order not found."

        });

      }


      if(
        Number(order.user_id) !==
        Number(req.session.userId)
      ){

        return res.status(403).json({

          success:false,

          message:
            "You cannot pay for this order."

        });

      }


      if(
        order.payment_method !==
        "binance"
      ){

        return res.status(400).json({

          success:false,

          message:
            "This order is not a Binance Pay order."

        });

      }


      if(
        order.payment_status ===
        "paid"
      ){

        return res.json({

          success:true,

          paid:true,

          merchantTradeNo:
            order.binance_merchant_trade_no,

          prepayId:
            order.binance_prepay_id,

          checkoutUrl:""

        });

      }


      const merchantTradeNo =
        order.binance_merchant_trade_no ||
        (
          "DW" +
          order.order_number
            .replace(
              /[^a-zA-Z0-9]/g,
              ""
            )
        )
          .slice(
            0,
            32
          );


      const returnUrl =
        getBaseUrl(req) +
        "/?payment=binance&order=" +
        encodeURIComponent(
          order.order_number
        );


      const cancelUrl =
        getBaseUrl(req) +
        "/?payment=binance&order=" +
        encodeURIComponent(
          order.order_number
        );


      const requestBody = {

        env:{

          terminalType:
            "WEB"

        },

        merchantTradeNo,

        orderAmount:
          Number(
            order.amount_crypto
          ).toFixed(2),

        currency:
          BINANCE_CURRENCY,

        goods:{

          goodsType:
            "02",

          goodsCategory:
            "Z000",

          referenceGoodsId:
            String(
              order.product_id
            ),

          goodsName:
            order.product_name,

          goodsDetail:
            order.product_description ||
            order.product_name

        },

        returnUrl,

        cancelUrl

      };


      const response =
        await binanceRequest(
          BINANCE_CREATE_PATH,
          requestBody
        );


      if(
        !response ||
        response.status !==
          "SUCCESS"
      ){

        throw new Error(

          response?.errorMessage ||
          response?.message ||
          "Binance order creation failed."

        );

      }


      const result =
        response.data ||
        {};


      const prepayId =
        result.prepayId ||
        result.prepay_id ||
        "";


      const checkoutUrl =
        result.checkoutUrl ||
        result.checkout_url ||
        result.qrContent ||
        result.universalUrl ||
        "";


      if(!checkoutUrl){

        throw new Error(
          "Binance checkout URL was not returned."
        );

      }


      db.prepare(`
        UPDATE orders

        SET

          binance_merchant_trade_no = ?,

          binance_prepay_id = ?

        WHERE
          id = ?

      `).run(

        merchantTradeNo,

        prepayId,

        order.id

      );


      res.json({

        success:true,

        merchantTradeNo,

        prepayId,

        checkoutUrl

      });

    }catch(error){

      console.error(
        "BINANCE CREATE ERROR:",
        error.response?.data ||
        error
      );

      res.status(500).json({

        success:false,

        message:
          error.response?.data?.errorMessage ||
          error.response?.data?.message ||
          error.message ||
          "Unable to create Binance payment."

      });

    }

  }
);


/* =========================================================
   BINANCE QUERY
========================================================= */

async function queryBinanceOrder(
  merchantTradeNo
){

  return await binanceRequest(

    BINANCE_QUERY_PATH,

    {

      merchantTradeNo

    }

  );

}


/* =========================================================
   VERIFY BINANCE ORDER
========================================================= */

async function verifyBinanceOrder(
  order
){

  if(
    !order.binance_merchant_trade_no
  ){

    return {

      paid:false,

      status:
        "NOT_CREATED"

    };

  }


  const response =
    await queryBinanceOrder(
      order.binance_merchant_trade_no
    );


  if(
    !response ||
    response.status !==
      "SUCCESS"
  ){

    return {

      paid:false,

      status:
        response?.status ||
        "UNKNOWN",

      message:
        response?.errorMessage ||
        response?.message ||
        "Binance query failed."

    };

  }


  const data =
    response.data ||
    {};


  const status =
    String(
      data.status ||
      ""
    ).toUpperCase();


  const amount =
    Number(
      data.orderAmount
    );


  const currency =
    String(
      data.currency ||
      ""
    ).toUpperCase();


  const expectedAmount =
    Number(
      order.amount_crypto
    );


  const exactAmount =
    Number.isFinite(amount) &&
    Math.abs(
      amount -
      expectedAmount
    ) < 0.000001;


  const exactCurrency =
    currency ===
    BINANCE_CURRENCY;


  const paid =
    status === "PAID" &&
    exactAmount &&
    exactCurrency;


  return {

    paid,

    status,

    transactionId:
      data.transactionId ||
      data.transaction_id ||
      data.transId ||
      "",

    txId:
      data.transactionId ||
      data.transaction_id ||
      data.transId ||
      "",

    amount,

    currency,

    raw:data

  };

}


/* =========================================================
   BINANCE CHECK
========================================================= */

app.get(
  "/api/binance/check/:orderNumber",
  requireLogin,
  async function(
    req,
    res
  ){

    try{

      if(
        !BINANCE_CERTIFICATE_SN ||
        !BINANCE_SECRET_KEY
      ){

        return res.status(503).json({

          success:false,

          paid:false,

          message:
            "Binance Pay is not configured."

        });

      }


      const orderNumber =
        cleanText(
          req.params.orderNumber
        );


      const order =
        getOrderByNumber(
          orderNumber
        );


      if(!order){

        return res.status(404).json({

          success:false,

          paid:false,

          message:
            "Order not found."

        });

      }


      if(
        Number(order.user_id) !==
        Number(req.session.userId)
      ){

        return res.status(403).json({

          success:false,

          paid:false,

          message:
            "You cannot check this order."

        });

      }


      if(
        order.payment_method !==
        "binance"
      ){

        return res.status(400).json({

          success:false,

          paid:false,

          message:
            "This is not a Binance order."

        });

      }


      if(
        order.payment_status ===
        "paid"
      ){

        return res.json({

          success:true,

          paid:true,

          status:"PAID",

          transactionId:
            order.binance_transaction_id ||
            "",

          orderNumber:
            order.order_number

        });

      }


      const result =
        await verifyBinanceOrder(
          order
        );


      if(result.paid){

        db.prepare(`
          UPDATE orders

          SET

            payment_status =
              'paid',

            binance_verified =
              1,

            binance_transaction_id =
              ?,

            binance_txid =
              ?,

            paid_at =
              COALESCE(
                paid_at,
                ?
              )

          WHERE
            id = ?

        `).run(

          result.transactionId ||
            "",

          result.txId ||
            "",

          now(),

          order.id

        );


        return res.json({

          success:true,

          paid:true,

          status:"PAID",

          transactionId:
            result.transactionId ||
            "",

          orderNumber:
            order.order_number

        });

      }


      res.json({

        success:true,

        paid:false,

        status:
          result.status ||
          "PENDING",

        orderNumber:
          order.order_number,

        message:
          result.message ||
          "Payment is not confirmed yet."

      });

    }catch(error){

      console.error(
        "BINANCE CHECK ERROR:",
        error.response?.data ||
        error
      );

      res.status(500).json({

        success:false,

        paid:false,

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

app.post(
  "/api/binance/webhook",
  async function(
    req,
    res
  ){

    try{

      const body =
        req.body ||
        {};


      const merchantTradeNo =
        body.merchantTradeNo ||
        body.data?.merchantTradeNo ||
        "";


      if(
        !merchantTradeNo
      ){

        return res.json({

          success:true

        });

      }


      const order =
        db.prepare(`
          SELECT *
          FROM orders
          WHERE
            binance_merchant_trade_no = ?
        `).get(
          merchantTradeNo
        );


      if(!order){

        return res.json({

          success:true

        });

      }


      const result =
        await verifyBinanceOrder(
          order
        );


      if(result.paid){

        db.prepare(`
          UPDATE orders

          SET

            payment_status =
              'paid',

            binance_verified =
              1,

            binance_transaction_id =
              ?,

            binance_txid =
              ?,

            paid_at =
              COALESCE(
                paid_at,
                ?
              )

          WHERE
            id = ?

        `).run(

          result.transactionId ||
            "",

          result.txId ||
            "",

          now(),

          order.id

        );

      }


      res.json({

        success:true

      });

    }catch(error){

      console.error(
        "BINANCE WEBHOOK ERROR:",
        error
      );

      res.json({

        success:true

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
  function(
    req,
    res
  ){

    try{

      const users =
        db.prepare(`
          SELECT
            id,
            name,
            email,
            is_admin,
            created_at
          FROM users
          ORDER BY id DESC
        `).all();


      res.json({

        success:true,

        users

      });

    }catch(error){

      console.error(
        "ADMIN USERS ERROR:",
        error
      );

      res.status(500).json({

        success:false,

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
  function(
    req,
    res
  ){

    try{

      const orders =
        db.prepare(`
          SELECT

            o.*,

            p.name AS product_name,

            u.name AS user_name,

            u.email AS user_email

          FROM orders o

          LEFT JOIN products p
            ON p.id = o.product_id

          LEFT JOIN users u
            ON u.id = o.user_id

          ORDER BY
            o.id DESC

        `).all();


      res.json({

        success:true,

        orders

      });

    }catch(error){

      console.error(
        "ADMIN ORDERS ERROR:",
        error
      );

      res.status(500).json({

        success:false,

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
  async function(
    req,
    res
  ){

    try{

      const orderNumber =
        cleanText(
          req.params.orderNumber
        );


      const order =
        getOrderByNumber(
          orderNumber
        );


      if(!order){

        return res.status(404).json({

          success:false,

          paid:false,

          message:
            "Order not found."

        });

      }


      if(
        order.payment_status ===
        "paid"
      ){

        return res.json({

          success:true,

          paid:true,

          message:
            "Payment is already confirmed."

        });

      }


      if(
        order.payment_method ===
        "paystack"
      ){

        if(
          !PAYSTACK_SECRET_KEY
        ){

          return res.status(503).json({

            success:false,

            paid:false,

            message:
              "Paystack is not configured."

          });

        }


        const reference =
          order.paystack_reference ||
          order.order_number;


        const response =
          await axios.get(

            "https://api.paystack.co/transaction/verify/" +
            encodeURIComponent(
              reference
            ),

            {

              headers:{

                Authorization:
                  `Bearer ${PAYSTACK_SECRET_KEY}`

              },

              timeout:
                20000

            }

          );


        const transaction =
          response.data?.data;


        const confirmed =
          response.data?.status === true &&
          transaction?.status ===
            "success" &&
          Number(transaction.amount) ===
            Math.round(
              Number(order.amount_kes) *
              100
            ) &&
          String(
            transaction.currency ||
            ""
          ).toUpperCase() ===
            PAYSTACK_CURRENCY;


        if(confirmed){

          db.prepare(`
            UPDATE orders

            SET

              payment_status =
                'paid',

              paystack_reference =
                ?,

              paystack_transaction_id =
                ?,

              paystack_receipt =
                ?,

              paid_at =
                COALESCE(
                  paid_at,
                  ?
                )

            WHERE
              id = ?

          `).run(

            transaction.reference ||
              reference,

            transaction.id
              ? String(transaction.id)
              : "",

            transaction.receipt_number
              ? String(
                  transaction.receipt_number
                )
              : "",

            now(),

            order.id

          );


          return res.json({

            success:true,

            paid:true,

            message:
              "Paystack payment confirmed."

          });

        }


        return res.json({

          success:true,

          paid:false,

          message:
            "Paystack payment is not confirmed."

        });

      }


      if(
        order.payment_method ===
        "binance"
      ){

        if(
          !BINANCE_CERTIFICATE_SN ||
          !BINANCE_SECRET_KEY
        ){

          return res.status(503).json({

            success:false,

            paid:false,

            message:
              "Binance Pay is not configured."

          });

        }


        const result =
          await verifyBinanceOrder(
            order
          );


        if(result.paid){

          db.prepare(`
            UPDATE orders

            SET

              payment_status =
                'paid',

              binance_verified =
                1,

              binance_transaction_id =
                ?,

              binance_txid =
                ?,

              paid_at =
                COALESCE(
                  paid_at,
                  ?
                )

            WHERE
              id = ?

          `).run(

            result.transactionId ||
              "",

            result.txId ||
              "",

            now(),

            order.id

          );


          return res.json({

            success:true,

            paid:true,

            message:
              "Binance payment confirmed."

          });

        }


        return res.json({

          success:true,

          paid:false,

          message:
            "Binance payment is not confirmed."

        });

      }


      res.status(400).json({

        success:false,

        paid:false,

        message:
          "Unsupported payment method."

      });

    }catch(error){

      console.error(
        "ADMIN CHECK PAYMENT ERROR:",
        error.response?.data ||
        error
      );

      res.status(500).json({

        success:false,

        paid:false,

        message:
          error.response?.data?.errorMessage ||
          error.response?.data?.message ||
          error.message ||
          "Unable to verify payment."

      });

    }

  }
);


/* =========================================================
   ADMIN DELIVERY
========================================================= */

app.post(
  "/api/admin/orders/:orderNumber/delivery",
  requireAdmin,
  function(
    req,
    res
  ){

    try{

      const orderNumber =
        cleanText(
          req.params.orderNumber
        );


      /*
       * Your HTML sends BOTH:
       *
       * deliveryNotes
       * delivery_notes
       */

      const deliveryNotes =
        cleanText(
          req.body.delivery_notes ??
          req.body.deliveryNotes ??
          ""
        );


      const order =
        getOrderByNumber(
          orderNumber
        );


      if(!order){

        return res.status(404).json({

          success:false,

          message:
            "Order not found."

        });

      }


      if(
        order.payment_status !==
        "paid"
      ){

        return res.status(400).json({

          success:false,

          message:
            "Payment must be confirmed before delivery."

        });

      }


      db.prepare(`
        UPDATE orders

        SET

          delivery_status =
            'delivered',

          delivery_notes =
            ?,

          delivered_at =
            COALESCE(
              delivered_at,
              ?
            )

        WHERE
          id = ?

      `).run(

        deliveryNotes,

        now(),

        order.id

      );


      res.json({

        success:true,

        message:
          "Delivery updated successfully."

      });

    }catch(error){

      console.error(
        "DELIVERY ERROR:",
        error
      );

      res.status(500).json({

        success:false,

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
  function(
    req,
    res
  ){

    try{

      const users =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM users
        `).get().count;


      const products =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM products
        `).get().count;


      const activeProducts =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM products
          WHERE active = 1
        `).get().count;


      const orders =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM orders
        `).get().count;


      const paid =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM orders
          WHERE payment_status = 'paid'
        `).get().count;


      const revenueKes =
        db.prepare(`
          SELECT
            COALESCE(
              SUM(amount_kes),
              0
            ) AS total

          FROM orders

          WHERE
            payment_status = 'paid'
            AND payment_method = 'paystack'
        `).get().total;


      const revenueUsdt =
        db.prepare(`
          SELECT
            COALESCE(
              SUM(amount_crypto),
              0
            ) AS total

          FROM orders

          WHERE
            payment_status = 'paid'
            AND payment_method = 'binance'
        `).get().total;


      res.json({

        success:true,

        users:
          Number(users),

        products:
          Number(products),

        activeProducts:
          Number(activeProducts),

        orders:
          Number(orders),

        paid:
          Number(paid),

        revenueKes:
          money(revenueKes),

        revenueUsdt:
          money(revenueUsdt)

      });

    }catch(error){

      console.error(
        "ADMIN STATS ERROR:",
        error
      );

      res.status(500).json({

        success:false,

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
  function(
    req,
    res
  ){

    res.json({

      success:true,

      service:
        "DARK WEB DIGITAL STORE",

      status:
        "online",

      payments:{

        paystack:
          Boolean(
            PAYSTACK_SECRET_KEY
          ),

        binance:
          Boolean(
            BINANCE_CERTIFICATE_SN &&
            BINANCE_SECRET_KEY
          )

      },

      timestamp:
        now()

    });

  }
);


/* =========================================================
   MULTER ERROR HANDLER
========================================================= */

app.use(
  function(
    error,
    req,
    res,
    next
  ){

    if(
      error instanceof
      multer.MulterError
    ){

      return res.status(400).json({

        success:false,

        message:
          error.code ===
            "LIMIT_FILE_SIZE"
            ?
            "Image is too large. Maximum size is 5MB."
            :
            error.message

      });

    }


    if(
      error
    ){

      console.error(
        "SERVER ERROR:",
        error
      );


      if(
        req.path.startsWith(
          "/api/"
        )
      ){

        return res.status(500).json({

          success:false,

          message:
            error.message ||
            "Server error."

        });

      }

    }


    next();

  }
);


/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.get(
  "*splat",
  function(
    req,
    res
  ){

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
  function(){

    console.log(
      "======================================"
    );

    console.log(
      "DARK WEB DIGITAL STORE"
    );

    console.log(
      "Server running on port:",
      PORT
    );

    console.log(
      "ADMIN:",
      ADMIN_EMAIL
        ? ADMIN_EMAIL
        : "NOT CONFIGURED"
    );

    console.log(
      "PAYSTACK:",
      PAYSTACK_SECRET_KEY
        ? "CONFIGURED"
        : "NOT CONFIGURED"
    );

    console.log(
      "BINANCE:",
      (
        BINANCE_CERTIFICATE_SN &&
        BINANCE_SECRET_KEY
      )
        ? "CONFIGURED"
        : "NOT CONFIGURED"
    );

    console.log(
      "DATABASE:",
      DB_PATH
    );

    console.log(
      "======================================"
    );

  }
);


/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

function shutdown(){

  console.log(
    "Shutting down..."
  );

  try{

    db.close();

  }catch(error){

    console.error(error);

  }

  process.exit(0);

}


process.on(
  "SIGINT",
  shutdown
);

process.on(
  "SIGTERM",
  shutdown
);
