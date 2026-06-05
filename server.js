const multer = require("multer");
const upload = multer({ dest: "uploads/" });

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Stripe = require("stripe");

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 10000;

const JWT_SECRET = process.env.JWT_SECRET || "stitchvale_secret_key";

const usersFile = path.join(__dirname, "users.json");
const productsFile = path.join(__dirname, "products.json");
const ordersFile = path.join(__dirname, "orders.json");

/* ---------------- JSON HELPERS ---------------- */
function readJSON(file) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, "[]");

  const content = fs.readFileSync(file, "utf8").trim();

  if (!content) {
    fs.writeFileSync(file, "[]");
    return [];
  }

  return JSON.parse(content);
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

/* ---------------- MIDDLEWARE ---------------- */
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

/* ---------------- STRIPE WEBHOOK ---------------- */
app.post("/webhook", express.raw({ type: "application/json" }), (req, res) => {
  const sig = req.headers["stripe-signature"];

  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.log("Webhook error:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;

    const orders = readJSON(ordersFile);

    const exists = orders.find(o => o.stripeSessionId === session.id);

    if (!exists) {
      orders.push({
        id: Date.now(),
        stripeSessionId: session.id,
        email: session.customer_details?.email,
        name: session.customer_details?.name,
        total: session.amount_total / 100,
        currency: session.currency,
        status: "paid",
        createdAt: new Date().toISOString()
      });

      writeJSON(ordersFile, orders);
      console.log("Ordine salvato");
    }
  }

  res.json({ received: true });
});

/* ---------------- REGISTER ---------------- */
app.post("/register", async (req, res) => {
  const { email, password, role } = req.body;

  const users = readJSON(usersFile);
  const cleanEmail = email.toLowerCase().trim();

  if (users.find(u => u.email === cleanEmail)) {
    return res.status(400).json({ message: "Utente già registrato" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: Date.now(),
    email: cleanEmail,
    password: hashedPassword,
    role: role === "brand" ? "brand" : "user",
    approved: role === "brand" ? false : true,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  writeJSON(usersFile, users);

  res.json({
    message: role === "brand"
      ? "Registrazione brand inviata"
      : "Registrazione completata"
  });
});

/* ---------------- LOGIN ---------------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const users = readJSON(usersFile);
  const cleanEmail = email.toLowerCase().trim();

  const user = users.find(u => u.email === cleanEmail);

  if (!user) return res.status(400).json({ message: "Utente non trovato" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ message: "Password errata" });

  if (user.role === "brand" && user.approved !== true) {
    return res.status(403).json({
      message: "Account brand non approvato"
    });
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      approved: user.approved
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ token, email: user.email, role: user.role });
});

/* ---------------- AUTH ---------------- */
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) return res.status(401).json({ message: "Token mancante" });

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Token non valido" });
  }
}

/* ---------------- BRAND CHECK ---------------- */
function requireApprovedBrand(req, res, next) {
  const users = readJSON(usersFile);

  const user = users.find(u => u.email === req.user.email);

  if (!user || user.approved !== true) {
    return res.status(403).json({
      message: "Account brand non approvato"
    });
  }

  next();
}

/* ---------------- PRODUCTS ---------------- */
app.get("/products", (req, res) => {
  res.json(readJSON(productsFile));
});

app.post(
  "/products",
  auth,
  requireApprovedBrand,
  upload.array("images", 8),
  (req, res) => {
    console.log("BODY:", req.body);
    console.log("FILES:", req.files);

    const products = readJSON(productsFile);

    const images = req.files ? req.files.map(f => f.filename) : [];

    const product = {
      id: Date.now(),
      name: req.body.name,
      brand: req.user.email,
      category: req.body.category,
      description: req.body.description,
      price: Number(req.body.price || 0),
      images: images,
      image: images[0] || "",
      createdAt: new Date().toISOString(),
      createdBy: req.user.email
    };

    products.push(product);
    writeJSON(productsFile, products);

    res.json({
      message: "Prodotto aggiunto",
      product
    });
  }
);

/* ---------------- ORDERS ---------------- */
app.get("/orders", auth, (req, res) => {
  const orders = readJSON(ordersFile);
  res.json(orders.filter(o => o.email === req.user.email));
});

/* ---------------- ADMIN SIMPLE ---------------- */
app.get("/admin-users", (req, res) => {
  if (req.query.password !== "STITCHVALEADMIN") {
    return res.status(403).json({ message: "No access" });
  }

  const users = readJSON(usersFile).map(u => ({
    id: u.id,
    email: u.email,
    role: u.role,
    approved: u.approved
  }));

  res.json(users);
});

app.get("/admin-orders", (req, res) => {
  if (req.query.password !== "STITCHVALEADMIN") {
    return res.status(403).json({ message: "No access" });
  }

  res.json(readJSON(ordersFile));
});

/* ---------------- APPROVE BRAND ---------------- */
app.post("/approve-brand", (req, res) => {
  const { password, email } = req.body;

  if (password !== "STITCHVALEADMIN") {
    return res.status(403).json({ message: "No access" });
  }

  const users = readJSON(usersFile);
  const user = users.find(u => u.email === email);

  if (!user) return res.status(404).json({ message: "Not found" });

  user.approved = true;

  writeJSON(usersFile, users);

  res.json({ message: "Brand approvato" });
});

/* ---------------- STRIPE ---------------- */
app.post("/create-checkout-session", async (req, res) => {
  const { name, price } = req.body;

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    mode: "payment",
    line_items: [
      {
        price_data: {
          currency: "eur",
          product_data: { name },
          unit_amount: Math.round(price * 100)
        },
        quantity: 1
      }
    ],
    success_url: "https://www.stitchvale.com/success.html",
    cancel_url: "https://www.stitchvale.com/cancel.html"
  });

  res.json({ url: session.url });
});

/* ---------------- START ---------------- */
app.listen(PORT, () => {
  console.log("Server avviato su porta " + PORT);
});

