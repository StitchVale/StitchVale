const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Stripe = require("stripe");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

/* ================= ENV ================= */
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

/* ================= SUPABASE ================= */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

/* ================= MIDDLEWARE ================= */
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const upload = multer({ dest: "uploads/" });

/* ================= AUTH ================= */
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ message: "Token mancante" });
  }

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Token non valido" });
  }
}

/* ================= REGISTER ================= */
app.post("/register", async (req, res) => {
  const { email, password, role } = req.body;

  const cleanEmail = email.toLowerCase().trim();

  const { data: existing } = await supabase
    .from("users")
    .select("*")
    .eq("email", cleanEmail);

  if (existing && existing.length > 0) {
    return res.status(400).json({ message: "Utente già registrato" });
  }

  const hashed = await bcrypt.hash(password, 10);

  const { error } = await supabase.from("users").insert([
    {
      email: cleanEmail,
      password: hashed,
      role: role === "brand" ? "brand" : "user",
      approved: role === "brand" ? false : true,
      created_at: new Date().toISOString()
    }
  ]);

  if (error) return res.status(500).json(error);

  res.json({
    message: role === "brand"
      ? "Registrazione brand inviata"
      : "Registrazione completata"
  });
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const cleanEmail = email.toLowerCase().trim();

  const { data } = await supabase
    .from("users")
    .select("*")
    .eq("email", cleanEmail);

  const user = data?.[0];

  if (!user) {
    return res.status(400).json({ message: "Utente non trovato" });
  }

  const ok = await bcrypt.compare(password, user.password);

  if (!ok) {
    return res.status(400).json({ message: "Password errata" });
  }

  if (user.role === "brand" && user.approved !== true) {
    return res.status(403).json({ message: "Brand non approvato" });
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

  res.json({
    token,
    email: user.email,
    role: user.role
  });
});

/* ================= PRODUCTS ================= */
app.get("/products", async (req, res) => {
  const { data, error } = await supabase.from("products").select("*");

  if (error) return res.status(500).json(error);

  res.json(data);
});

app.post(
  "/products",
  auth,
  upload.array("images", 8),
  async (req, res) => {
    const images = req.files ? req.files.map(f => f.filename) : [];

    const { error } = await supabase.from("products").insert([
      {
        name: req.body.name,
        brand: req.user.email,
        category: req.body.category,
        description: req.body.description,
        price: Number(req.body.price),
        images: images,
        image: images[0] || "",
        created_at: new Date().toISOString(),
        created_by: req.user.email
      }
    ]);

    if (error) return res.status(500).json(error);

    res.json({ message: "Prodotto creato" });
  }
);

/* ================= ORDERS ================= */
app.get("/orders", auth, async (req, res) => {
  const { data } = await supabase
    .from("orders")
    .select("*")
    .eq("email", req.user.email);

  res.json(data);
});

/* ================= APPROVE BRAND (ADMIN) ================= */
app.post("/approve-brand", async (req, res) => {
  const { password, email } = req.body;

  if (password !== "STITCHVALEADMIN") {
    return res.status(403).json({ message: "No access" });
  }

  const { error } = await supabase
    .from("users")
    .update({ approved: true })
    .eq("email", email);

  if (error) return res.status(500).json(error);

  res.json({ message: "Brand approvato" });
});

/* ================= ADMIN USERS ================= */
app.get("/admin-users", async (req, res) => {
  if (req.query.password !== "STITCHVALEADMIN") {
    return res.status(403).json({ message: "No access" });
  }

  const { data } = await supabase.from("users").select("*");
  res.json(data);
});

/* ================= ADMIN ORDERS ================= */
app.get("/admin-orders", async (req, res) => {
  if (req.query.password !== "STITCHVALEADMIN") {
    return res.status(403).json({ message: "No access" });
  }

  const { data } = await supabase.from("orders").select("*");
  res.json(data);
});

/* ================= STRIPE ================= */
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

/* ================= START ================= */
app.listen(PORT, () => {
  console.log("Server Supabase attivo su porta " + PORT);
});
