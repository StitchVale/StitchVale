const express = require("express");
const cors = require("cors");
const fs = require("fs");
const multer = require("multer");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));
app.use(express.static(__dirname));

const upload = multer({ dest: "uploads/" });

const IDEAS_FILE = "ideas.json";
const USERS_FILE = "users.json";
const PRODUCTS_FILE = "products.json";
const BRANDS_FILE = "brands.json";
const ORDERS_FILE = "orders.json";

const SECRET = "stitchvale_secret_key";

function readFile(file) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify([]));
  }

  const content = fs.readFileSync(file, "utf8").trim();

  if (!content) {
    fs.writeFileSync(file, JSON.stringify([]));
    return [];
  }

  return JSON.parse(content);
}

function saveFile(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function clean(text) {
  return String(text || "").trim();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Devi effettuare il login" });
  }

  const token = authHeader.split(" ")[1];

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Sessione scaduta" });
  }
}

function requireBrand(req, res, next) {
  if (req.user.role !== "brand") {
    return res.status(403).json({ message: "Solo i brand possono fare questa azione" });
  }

  next();
}

/* HOME COUNTDOWN */
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

/* IDEE */
app.post("/upload", verifyToken, upload.array("images", 8), (req, res) => {
  const title = clean(req.body.title);
  const description = clean(req.body.description);
  const contact = clean(req.body.contact);

  if (!title || !description || !contact) {
    return res.status(400).json({ message: "Campi obbligatori mancanti" });
  }

  const ideas = readFile(IDEAS_FILE);
  const images = req.files ? req.files.map(f => f.filename) : [];

  const newIdea = {
    id: Date.now(),
    title,
    description,
    contact,
    images,
    image: images[0] || null,
    likes: 0,
    createdBy: req.user.email,
    createdAt: new Date().toISOString()
  };

  ideas.push(newIdea);
  saveFile(IDEAS_FILE, ideas);

  res.json(newIdea);
});

app.get("/ideas", (req, res) => {
  const ideas = readFile(IDEAS_FILE);
  ideas.sort((a, b) => b.likes - a.likes);
  res.json(ideas);
});

app.post("/like/:id", verifyToken, (req, res) => {
  const ideas = readFile(IDEAS_FILE);
  const idea = ideas.find(i => i.id == req.params.id);

  if (!idea) {
    return res.status(404).json({ message: "Idea non trovata" });
  }

  idea.likes++;
  saveFile(IDEAS_FILE, ideas);

  res.json(idea);
});

/* UTENTI */
app.post("/register", async (req, res) => {
  const email = clean(req.body.email).toLowerCase();
  const password = clean(req.body.password);
  const role = clean(req.body.role) === "brand" ? "brand" : "user";

  if (!isValidEmail(email)) {
    return res.status(400).json({ message: "Email non valida" });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: "Password troppo corta" });
  }

  const users = readFile(USERS_FILE);

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: "Utente già registrato" });
  }

  const hashed = await bcrypt.hash(password, 10);

  users.push({
    id: Date.now(),
    email,
    password: hashed,
    role,
    createdAt: new Date().toISOString()
  });

  saveFile(USERS_FILE, users);

  res.json({ message: "Registrazione completata" });
});

app.post("/login", async (req, res) => {
  const email = clean(req.body.email).toLowerCase();
  const password = clean(req.body.password);

  const users = readFile(USERS_FILE);
  const user = users.find(u => u.email === email);

  if (!user) {
    return res.status(400).json({ message: "Utente non trovato" });
  }

  const valid = await bcrypt.compare(password, user.password);

  if (!valid) {
    return res.status(400).json({ message: "Password errata" });
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    SECRET,
    { expiresIn: "7d" }
  );

  res.json({
    message: "Login riuscito",
    token,
    email: user.email,
    role: user.role
  });
});

/* PRODOTTI */
app.post("/products", verifyToken, requireBrand, upload.array("images", 8), (req, res) => {
  const name = clean(req.body.name);
  const category = clean(req.body.category);
  const description = clean(req.body.description);
  const price = Number(req.body.price);

  const brands = readFile(BRANDS_FILE);
  const brandProfile = brands.find(b => b.createdBy === req.user.email);

  if (!brandProfile) {
    return res.status(400).json({ message: "Crea prima il profilo brand" });
  }

  if (!name || !category || !description) {
    return res.status(400).json({ message: "Campi mancanti" });
  }

  if (!price || price <= 0) {
    return res.status(400).json({ message: "Prezzo non valido" });
  }

  const products = readFile(PRODUCTS_FILE);
  const images = req.files ? req.files.map(f => f.filename) : [];

  const newProduct = {
    id: Date.now(),
    name,
    brand: brandProfile.name,
    category,
    description,
    price,
    images,
    image: images[0] || null,
    createdAt: new Date().toISOString(),
    createdBy: req.user.email
  };

  products.push(newProduct);
  saveFile(PRODUCTS_FILE, products);

  res.json({
    message: "Prodotto caricato",
    product: newProduct
  });
});

app.get("/products", (req, res) => {
  const products = readFile(PRODUCTS_FILE);
  products.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  res.json(products);
});

/* BRAND */
app.post("/brands", verifyToken, requireBrand, upload.single("logo"), (req, res) => {
  const name = clean(req.body.name);
  const bio = clean(req.body.bio);

  if (!name || !bio) {
    return res.status(400).json({ message: "Campi mancanti" });
  }

  const brands = readFile(BRANDS_FILE);
  const existing = brands.find(b => b.createdBy === req.user.email);

  if (existing) {
    existing.name = name;
    existing.bio = bio;
    existing.logo = req.file ? req.file.filename : existing.logo;
    existing.updatedAt = new Date().toISOString();
    existing.updatedBy = req.user.email;

    saveFile(BRANDS_FILE, brands);

    return res.json({
      message: "Brand aggiornato",
      brand: existing
    });
  }

  const newBrand = {
    id: Date.now(),
    name,
    bio,
    logo: req.file ? req.file.filename : null,
    createdBy: req.user.email,
    createdAt: new Date().toISOString()
  };

  brands.push(newBrand);
  saveFile(BRANDS_FILE, brands);

  res.json({
    message: "Brand creato",
    brand: newBrand
  });
});

app.get("/brands", (req, res) => {
  res.json(readFile(BRANDS_FILE));
});

/* ORDINI */
app.post("/orders", verifyToken, (req, res) => {
  const orders = readFile(ORDERS_FILE);

  const newOrder = {
    id: Date.now(),
    customer: req.body.customer,
    items: req.body.items,
    total: req.body.total,
    paymentMethod: req.body.paymentMethod,
    notes: req.body.notes,
    createdAt: new Date().toISOString(),
    userEmail: req.user.email
  };

  orders.push(newOrder);
  saveFile(ORDERS_FILE, orders);

  res.json({
    message: "Ordine salvato",
    order: newOrder
  });
});

app.get("/orders", verifyToken, (req, res) => {
  const orders = readFile(ORDERS_FILE);

  const userOrders = orders
    .filter(o => o.userEmail === req.user.email)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

  res.json(userOrders);
});

/* SERVER */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server avviato su porta " + PORT);
});