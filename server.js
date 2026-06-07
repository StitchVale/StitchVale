const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Stripe = require("stripe");
const multer = require("multer");
const path = require("path"); // Gestisce le estensioni dei file (.jpg, .png)
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
// Rende accessibili al browser i file caricati nella cartella uploads
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Configurazione Multer: mantiene le estensioni originali dei file caricati
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

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

  if (error) {
    console.log(error);
    return res.status(500).json(error);
  }

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

/* ================= BRANDS PROFILE ================= */
app.post("/brands", auth, upload.single("logo"), async (req, res) => {
  try {
    const brandData = {
      name: req.body.name || "",
      bio: req.body.bio || "",
      style: req.body.style || "",
      website: req.body.website || "",
      instagram: req.body.instagram || "",
      email: req.user.email // Associa il profilo all'email del brand autenticato
    };

    // Se è stato caricato un file per il logo, inseriamo il nome del file generato
    if (req.file) {
      brandData.logo = req.file.filename;
    }

    // Controlla se il brand ha già creato un profilo in passato
    const { data: existingBrand } = await supabase
      .from("brand")
      .select("*")
      .eq("email", req.user.email);

    let result;
    if (existingBrand && existingBrand.length > 0) {
      // Se esiste già, aggiorna i dati attuali
      result = await supabase
        .from("brand")
        .update(brandData)
        .eq("email", req.user.email);
    } else {
      // Se è la prima volta, crea un record da zero
      result = await supabase
        .from("brand")
        .insert([brandData]);
    }

    if (result.error) {
      console.log("SUPABASE ERR:", result.error);
      return res.status(400).json(result.error);
    }

    res.json({ message: "Profilo brand salvato con successo!" });
  } catch (err) {
    console.log("SERVER ERR:", err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

/* ================= PRODUCTS ================= */
app.get("/products", async (req, res) => {
  const { data, error } = await supabase
    .from("products")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) {
    console.log(error);
    return res.status(500).json(error);
  }

  res.json(data);
});

app.post(
  "/products",
  auth,
  upload.array("images", 8),
  async (req, res) => {
    const images = req.files ? req.files.map(f => f.filename) : [];

    console.log("BODY:", req.body);
    console.log("IMAGES:", images);

    const { error } = await supabase.from("products").insert([
      {
        name: req.body.name || "",
        brand: req.user.email,
        category: req.body.category || "",
        description: req.body.description || "",
        price: Number(req.body.price) || 0,
        images: images || [],
        image: images?.[0] || "",
        created_at: new Date().toISOString(),
        created_by: req.user.email
      }
    ]);

    if (error) {
      console.log("SUPABASE ERROR:", error);
      return res.status(400).json(error);
    }

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

/* ================= ADMIN ================= */
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

  app.get("/admin-users", async (req, res) => {
  if (req.query.password !== "STITCHVALEADMIN") {
    return res.status(403).json({ message: "No access" });
  }

  const { data } = await supabase.from("users").select("*");
  res.json(data);
});

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
