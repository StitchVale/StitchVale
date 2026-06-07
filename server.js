const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Stripe = require("stripe");
const multer = require("multer");
const path = require("path"); // Gestisce le estensioni dei file (.jpg, .png)
const fs = require("fs");
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

// Middleware di controllo per la cartella uploads per evitare crash se Render cancella le foto
app.use("/uploads/:file", (req, res, next) => {
  const filePath = path.join(__dirname, "uploads", req.params.file);
  
  if (fs.existsSync(filePath)) {
    return next();
  } else {
    return res.redirect("https://images.unsplash.com/photo-1515886657613-9f3515b0c78f?w=500&q=80");
  }
});

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Configurazione Multer Ottimizzata per prevenire sovrascritture di file
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    // Include il nome del campo (logo o images) + timestamp + numero casuale univoco
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);
    // Combina il fieldname originario con il suffisso e l'estensione del file originale (.jpg, .png, ecc.)
    cb(null, file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

/* ================= AUTH MIDDLEWARE ================= */
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
  try {
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
      console.error(error);
      return res.status(500).json(error);
    }

    res.json({
      message: role === "brand"
        ? "Registrazione brand inviata"
        : "Registrazione completata"
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
  try {
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

/* ================= BRANDS PROFILE (SALVATAGGIO) ================= */
app.post("/brands", auth, upload.single("logo"), async (req, res) => {
  try {
    const brandData = {
      name: req.body.name || "",
      bio: req.body.bio || "",
      style: req.body.style || "",
      website: req.body.website || "",
      instagram: req.body.instagram || "",
      email: req.user.email 
    };

    if (req.file && req.file.filename) {
      brandData.logo = req.file.filename;
    }

    const { data: existingBrand, error: checkError } = await supabase
      .from("brand")
      .select("*")
      .eq("email", req.user.email);

    if (checkError) {
      return res.status(400).json(checkError);
    }

    let result;
    if (existingBrand && existingBrand.length > 0) {
      result = await supabase
        .from("brand")
        .update(brandData)
        .eq("email", req.user.email);
    } else {
      result = await supabase
        .from("brand")
        .insert([brandData]);
    }

    if (result.error) {
      return res.status(400).json(result.error);
    }

    res.json({ message: "Profilo brand salvato con successo!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});    

/* ================= BRANDS LIST (RICHIESTA PUBBLICA PER IL CATALOGO) ================= */
app.get("/brands-list", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("brand")
      .select("email, name, logo, bio, style, instagram, website");

    if (error) {
      return res.status(400).json(error);
    }
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

/* ================= PRODUCTS ================= */
app.get("/products", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("products")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) {
      console.error(error);
      return res.status(500).json(error);
    }

    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

app.post("/products", auth, upload.array("images", 8), async (req, res) => {
  try {
    const images = req.files ? req.files.map(f => f.filename) : [];

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
      console.error("SUPABASE ERROR:", error);
      return res.status(400).json(error);
    }

    res.json({ message: "Prodotto creato" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

/* ================= ORDERS ================= */
app.get("/orders", auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("orders")
      .select("*")
      .eq("email", req.user.email);

    if (error) return res.status(400).json(error);
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

/* ================= ADMIN ================= */
app.post("/approve-brand", async (req, res) => {
  try {
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

app.get("/admin-users", async (req, res) => {
  try {
    if (req.query.password !== "STITCHVALEADMIN") {
      return res.status(403).json({ message: "No access" });
    }

    const { data, error } = await supabase.from("users").select("*");
    if (error) return res.status(400).json(error);
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

app.get("/admin-orders", async (req, res) => {
  try {
    if (req.query.password !== "STITCHVALEADMIN") {
      return res.status(403).json({ message: "No access" });
    }

    const { data, error } = await supabase.from("orders").select("*");
    if (error) return res.status(400).json(error);
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

/* ================= STRIPE ================= */
app.post("/create-checkout-session", async (req, res) => {
  try {
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore durante la creazione della sessione Stripe" });
  }
});

/* ================= START ================= */
app.listen(PORT, () => {
  console.log("Server Supabase attivo su porta " + PORT);
});
