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

// Gestione delle immagini tramite Supabase Storage (Redirect Automatico)
const SUPABASE_PROJECT_URL = process.env.SUPABASE_URL; 

app.get("/uploads/:file", (req, res) => {
  if (!SUPABASE_PROJECT_URL) {
    return res.status(500).json({ message: "Variabile SUPABASE_URL non configurata sul server" });
  }
  // Reindirizza il browser direttamente all'URL pubblico del file dentro il bucket di Supabase
  const publicUrl = `${SUPABASE_PROJECT_URL}/storage/v1/object/public/uploads/${req.params.file}`;
  return res.redirect(publicUrl);
});

// Configurazione Multer in Memoria (I file non toccano il disco di Render, vanno direttamente a Supabase)
const storage = multer.memoryStorage();
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
    const { email, password, role, username } = req.body;
    const cleanEmail = email.toLowerCase().trim();
    const cleanUsername = username ? username.trim() : null;

    // 1. Controllo se l'email esiste già
    const { data: existing } = await supabase
      .from("users")
      .select("*")
      .eq("email", cleanEmail);

    if (existing && existing.length > 0) {
      return res.status(400).json({ message: "Utente già registrato" });
    }

    // 2. Controllo opzionale: verifichiamo che l'username non sia già preso
    if (cleanUsername) {
      const { data: existingUser } = await supabase
        .from("users")
        .select("*")
        .eq("username", cleanUsername);

      if (existingUser && existingUser.length > 0) {
        return res.status(400).json({ message: "Questo username è già in uso" });
      }
    }

    const hashed = await bcrypt.hash(password, 10);

    // 3. Inserimento nel database con il nuovo campo username
    const { error } = await supabase.from("users").insert([
      {
        email: cleanEmail,
        username: cleanUsername,
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
        username: user.username,
        role: user.role,
        approved: user.approved
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      email: user.email,
      username: user.username,
      role: user.role
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

/* ================= BRANDS PROFILE (LOGO + COPERTINA COIL MODALITÀ MULTIPART) ================= */
app.post("/brands", auth, upload.fields([{ name: "logo", maxCount: 1 }, { name: "cover", maxCount: 1 }]), async (req, res) => {
  try {
    const brandData = {
      name: req.body.name || "",
      bio: req.body.bio || "",
      style: req.body.style || "",
      website: req.body.website || "",
      instagram: req.body.instagram || "",
      location: req.body.location || req.body.brandLocation || "",
      tiktok: req.body.tiktok || req.body.brandTikTok || "",
      slogan: req.body.slogan || req.body.brandSlogan || "",
      slug: req.body.slug || req.body.brandSlug || "",
      email: req.user.email 
    };

    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);

    // 1. Elaborazione e Upload del LOGO se inviato
    if (req.files && req.files["logo"] && req.files["logo"][0]) {
      const logoFile = req.files["logo"][0];
      const logoName = `logo-${uniqueSuffix}${path.extname(logoFile.originalname)}`;

      const { error: logoError } = await supabase.storage
        .from("uploads")
        .upload(logoName, logoFile.buffer, {
          contentType: logoFile.mimetype,
          upsert: true
        });

      if (!logoError) {
        brandData.logo = logoName;
      } else {
        console.error("Errore upload logo Supabase Storage:", logoError);
      }
    }

    // 2. Elaborazione e Upload dello SFONDO (cover) se inviato
    if (req.files && req.files["cover"] && req.files["cover"][0]) {
      const coverFile = req.files["cover"][0];
      const coverName = `cover-${uniqueSuffix}${path.extname(coverFile.originalname)}`;

      const { error: coverError } = await supabase.storage
        .from("uploads")
        .upload(coverName, coverFile.buffer, {
          contentType: coverFile.mimetype,
          upsert: true
        });

      if (!coverError) {
        brandData.cover = coverName;
      } else {
        console.error("Errore upload cover Supabase Storage:", coverError);
      }
    }

    const { data: existingBrand, error: checkError } = await supabase
      .from("brand")
      .select("*")
      .eq("email", req.user.email);

    if (checkError) {
      return res.status(400).json(checkError);
    }

    let data, error;
    if (existingBrand && existingBrand.length > 0) {
      const resUpdate = await supabase
        .from("brand")
        .update(brandData)
        .eq("email", req.user.email)
        .select();
      data = resUpdate.data;
      error = resUpdate.error;
    } else {
      const resInsert = await supabase
        .from("brand")
        .insert([brandData])
        .select();
      data = resInsert.data;
      error = resInsert.error;
    }

    if (error) {
      console.error("Errore salvataggio DB:", error);
      return res.status(400).json(error);
    }

    res.json({ message: "Profilo brand salvato con successo!", brand: data?.[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});    

/* ================= BRANDS LIST ================= */
app.get("/brands-list", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("brand")
      .select("email, name, logo, cover, bio, style, instagram, website, location, tiktok, slogan, slug");

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
    const { data, error = null } = await supabase
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
    const images = [];

    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);
        const fileName = `product-${uniqueSuffix}${path.extname(file.originalname)}`;

        const { error: uploadError } = await supabase.storage
          .from("uploads")
          .upload(fileName, file.buffer, {
            contentType: file.mimetype,
            upsert: true
          });

        if (!uploadError) {
          images.push(fileName);
        } else {
          console.error("Errore upload immagine prodotto Supabase:", uploadError);
        }
      }
    }

    const { data, error } = await supabase
      .from("products")
      .insert([
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
      ])
      .select();

    if (error) {
      console.error("SUPABASE ERROR:", error);
      return res.status(400).json(error);
    }

    res.json({ message: "Prodotto creato con successo!", product: data?.[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});
/* ================= UPDATE PRODUCT (MODIFICA) ================= */
app.put("/products/:id", auth, upload.array("images", 8), async (req, res) => {
  try {
    const productId = req.params.id;

    // 1. Verifichiamo prima se il prodotto esiste ed appartiene al brand che sta provando a modificarlo
    const { data: existingProduct, error: fetchError } = await supabase
      .from("products")
      .select("*")
      .eq("id", productId)
      .maybeSingle();

    if (fetchError || !existingProduct) {
      return res.status(404).json({ message: "Prodotto non trovato." });
    }

    if (existingProduct.brand !== req.user.email) {
      return res.status(403).json({ message: "Non hai i permessi per modificare questo prodotto." });
    }

    // 2. Prepariamo i dati aggiornati dal form
    const updatedData = {
      name: req.body.name || existingProduct.name,
      category: req.body.category || existingProduct.category,
      description: req.body.description || existingProduct.description,
      price: req.body.price ? Number(req.body.price) : existingProduct.price
    };

    // 3. Se l'utente ha caricato nuove immagini, le elaboriamo
    if (req.files && req.files.length > 0) {
      const newImages = [];
      for (const file of req.files) {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);
        const fileName = `product-${uniqueSuffix}${path.extname(file.originalname)}`;

        const { error: uploadError } = await supabase.storage
          .from("uploads")
          .upload(fileName, file.buffer, {
            contentType: file.mimetype,
            upsert: true
          });

        if (!uploadError) {
          newImages.push(fileName);
        } else {
          console.error("Errore upload immagine modifica:", uploadError);
        }
      }
      
      if (newImages.length > 0) {
        updatedData.images = newImages;
        updatedData.image = newImages[0]; // La prima diventa la principale
      }
    }

    // 4. Eseguiamo l'aggiornamento sul database
    const { data, error } = await supabase
      .from("products")
      .update(updatedData)
      .eq("id", productId)
      .select();

    if (error) {
      console.error("Errore update DB prodotti:", error);
      return res.status(400).json(error);
    }

    res.json({ message: "Prodotto aggiornato con successo!", product: data?.[0] });
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

    return res.json({ id: session.id });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore durante la creazione della sessione Stripe" });
  }
});

/* ================= IDEE ================= */
app.get("/ideas", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("idee")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Errore recupero idee:", error);
      return res.status(500).json(error);
    }

    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

app.post("/ideas", auth, upload.array("images", 8), async (req, res) => {
  try {
    const images = [];

    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);
        const fileName = `idea-${uniqueSuffix}${path.extname(file.originalname)}`;

        const { error: uploadError } = await supabase.storage
          .from("uploads")
          .upload(fileName, file.buffer, {
            contentType: file.mimetype,
            upsert: true
          });

        if (!uploadError) {
          images.push(fileName);
        } else {
          console.error("Errore upload immagine idea:", uploadError);
        }
      }
    }

    const { data, error } = await supabase
      .from("idee")
      .insert([
        {
          title: req.body.title || "",
          styleTag: req.body.styleTag || "",
          materials: req.body.materials || "",
          targetPrice: req.body.targetPrice || "",
          description: req.body.description || "",
          contact: req.body.contact || "",
          images: images, 
          brand: req.user.email,
          votes: 0, 
          created_at: new Date().toISOString()
        }
      ])
      .select();

    if (error) {
      console.error("Errore database idee:", error);
      return res.status(400).json(error);
    }

    res.json({ message: "Idea condivisa con successo!", idea: data?.[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Errore interno del server" });
  }
});

/* ================= ROTTA LIKE ================= */
app.post("/like/:id", auth, async (req, res) => {
  const ideaId = req.params.id;

  try {
    const { data: idea, error: fetchError } = await supabase
      .from("idee")
      .select("votes")
      .eq("id", ideaId)
      .maybeSingle();

    if (fetchError || !idea) {
      console.error("Errore recupero idea per like:", fetchError);
      return res.status(404).json({ message: "Idea non trovata nel DB", error: fetchError });
    }

    const nuoviVoti = (Number(idea.votes) || 0) + 1;

    const { data: updatedData, error: updateError } = await supabase
      .from("idee")
      .update({ votes: nuoviVoti })
      .eq("id", ideaId)
      .select();

    if (updateError || !updatedData || updatedData.length === 0) {
      console.error("Errore aggiornamento voti database:", updateError);
      return res.status(500).json({ 
        message: "Errore DB Supabase o violazione policy RLS", 
        detail: updateError 
      });
    }

    return res.json({ 
      message: "Voto registrato con successo!", 
      votes: updatedData[0].votes 
    });

  } catch (err) {
    console.error("Errore interno rotta like:", err);
    return res.status(500).json({ message: "Errore interno del server Render", error: err.message });
  }
});

/* ================= START ================= */
app.listen(PORT, () => {
  console.log("Server Supabase attivo su porta " + PORT);
});
