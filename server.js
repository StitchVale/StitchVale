const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Stripe = require("stripe");

const app = express();
const PORT = process.env.PORT || 10000;

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const JWT_SECRET = process.env.JWT_SECRET || "stitchvale_secret_key";

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const usersFile = path.join(__dirname, "users.json");
const productsFile = path.join(__dirname, "products.json");
const ordersFile = path.join(__dirname, "orders.json");

function readJSON(file) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, "[]");
  return JSON.parse(fs.readFileSync(file));
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

app.get("/", (req, res) => {
  res.send("Server StitchVale attivo");
});

/* REGISTER */
app.post("/register", async (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email e password obbligatorie" });
  }

  const users = readJSON(usersFile);

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: "Utente già registrato" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({
    id: Date.now(),
    email,
    password: hashedPassword,
    role: role || "user"
  });

  writeJSON(usersFile, users);

  res.json({ message: "Registrazione completata" });
});

/* LOGIN */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const users = readJSON(usersFile);
  const user = users.find(u => u.email === email);

  if (!user) {
    return res.status(400).json({ message: "Utente non trovato" });
  }

  const validPassword = await bcrypt.compare(password, user.password);

  if (!validPassword) {
    return res.status(400).json({ message: "Password errata" });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({
    message: "Login effettuato",
    token,
    email: user.email,
    role: user.role
  });
});

/* MIDDLEWARE TOKEN */
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
    res.status(401).json({ message: "Token non valido" });
  }
}

/* PRODUCTS */
app.get("/products", (req, res) => {
  const products = readJSON(productsFile);
  res.json(products);
});

app.post("/products", auth, (req, res) => {
  const products = readJSON(productsFile);

  const product = {
    id: Date.now(),
    name: req.body.name,
    brand: req.body.brand,
    category: req.body.category,
    description: req.body.description,
    price: Number(req.body.price),
    image: req.body.image || "",
    createdAt: new Date().toISOString(),
    createdBy: req.user.email
  };

  products.push(product);
  writeJSON(productsFile, products);

  res.json({ message: "Prodotto aggiunto", product });
});

/* ORDERS */
app.get("/orders", auth, (req, res) => {
  const orders = readJSON(ordersFile);
  const userOrders = orders.filter(order => order.email === req.user.email);
  res.json(userOrders);
});

/* STRIPE CHECKOUT */
app.post("/create-checkout-session", async (req, res) => {
  try {
    const { name, price } = req.body;

    if (!name || !price) {
      return res.status(400).json({ error: "Nome e prezzo obbligatori" });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      line_items: [
        {
          price_data: {
            currency: "eur",
            product_data: {
              name: name
            },
            unit_amount: Math.round(Number(price) * 100)
          },
          quantity: 1
        }
      ],
      success_url: "https://stitchvale-1.onrender.com/home.html",
      cancel_url: "https://stitchvale-1.onrender.com/checkout.html"
    });

    res.json({ url: session.url });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log("Server avviato su porta " + PORT);
});
