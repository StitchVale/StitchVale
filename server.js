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

/* CORS */
app.use(cors());

/* STRIPE WEBHOOK - deve stare PRIMA di express.json */
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
    console.log("Webhook signature error:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;

    console.log("Pagamento completato:", session.id);
    console.log("Email cliente:", session.customer_details?.email);
    console.log("Totale:", session.amount_total / 100);

    const orders = readJSON(ordersFile);

    const ordineEsisteGia = orders.find(
      order => order.stripeSessionId === session.id
    );

    if (!ordineEsisteGia) {
      const newOrder = {
        id: Date.now(),
        stripeSessionId: session.id,
        email: session.customer_details?.email || "Email non disponibile",
        name: session.customer_details?.name || "Nome non disponibile",
        total: session.amount_total / 100,
        currency: session.currency,
        status: "paid",
        paymentStatus: session.payment_status,
        createdAt: new Date().toISOString()
      };

      orders.push(newOrder);
      writeJSON(ordersFile, orders);

      console.log("Ordine salvato:", newOrder.id);
    } else {
      console.log("Ordine già salvato:", session.id);
    }
  }

  res.json({ received: true });
});

app.use(express.json());
app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.send("Server StitchVale attivo");
});

/* REGISTER */
app.post("/register", async (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "Email e password obbligatorie"
    });
  }

  const users = readJSON(usersFile);
  const cleanEmail = email.toLowerCase().trim();
  const userRole = role === "brand" ? "brand" : "user";

  if (users.find(u => u.email === cleanEmail)) {
    return res.status(400).json({
      message: "Utente già registrato"
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: Date.now(),
    email: cleanEmail,
    password: hashedPassword,
    role: userRole,
    approved: userRole === "brand" ? false : true,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  writeJSON(usersFile, users);

  if (userRole === "brand") {
    return res.json({
      message: "Registrazione brand inviata. Attendi approvazione."
    });
  }

  res.json({
    message: "Registrazione completata"
  });
});

/* LOGIN */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const users = readJSON(usersFile);
  const cleanEmail = email.toLowerCase().trim();

  const user = users.find(u => u.email === cleanEmail);

  if (!user) {
    return res.status(400).json({
      message: "Utente non trovato"
    });
  }

  const validPassword = await bcrypt.compare(password, user.password);

  if (!validPassword) {
    return res.status(400).json({
      message: "Password errata"
    });
  }

  if (user.role === "brand" && user.approved !== true) {
    return res.status(403).json({
      message: "Il tuo account brand è in attesa di approvazione."
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

  res.json({
    message: "Login effettuato",
    token,
    email: user.email,
    role: user.role,
    approved: user.approved
  });
});

/* MIDDLEWARE TOKEN */
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({
      message: "Token mancante"
    });
  }

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({
      message: "Token non valido"
    });
  }
}

/* SOLO BRAND APPROVATI */
function requireApprovedBrand(req, res, next) {
  if (req.user.role !== "brand") {
    return res.status(403).json({
      message: "Solo i brand possono fare questa azione"
    });
  }

  const users = readJSON(usersFile);
  const user = users.find(u => u.email === req.user.email);

  if (!user || user.approved !== true) {
    return res.status(403).json({
      message: "Account brand non approvato"
    });
  }

  next();
}

/* PRODUCTS */
app.get("/products", (req, res) => {
  const products = readJSON(productsFile);
  res.json(products);
});

app.post("/products", auth, requireApprovedBrand, (req, res) => {
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

  res.json({
    message: "Prodotto aggiunto",
    product
  });
});

/* ORDERS UTENTE */
app.get("/orders", auth, (req, res) => {
  const orders = readJSON(ordersFile);
  const userOrders = orders.filter(order => order.email === req.user.email);
  res.json(userOrders);
});

/* ADMIN ORDERS */
app.get("/admin-orders", (req, res) => {
  const password = req.query.password;

  if (password !== "STITCHVALEADMIN") {
    return res.status(403).json({
      message: "Accesso negato"
    });
  }

  const orders = readJSON(ordersFile);
  res.json(orders);
});
/* ADMIN USERS */
app.get("/admin-users", (req, res) => {
  const password = req.query.password;

  if (password !== "STITCHVALEADMIN") {
    return res.status(403).json({
      message: "Accesso negato"
    });
  }

  const users = readJSON(usersFile).map(user => ({
    id: user.id,
    email: user.email,
    role: user.role,
    approved: user.approved,
    createdAt: user.createdAt
  }));

  res.json(users);
});

/* BRAND IN ATTESA */
app.get("/pending-brands", (req, res) => {
  const password = req.query.password;

  if (password !== "STITCHVALEADMIN") {
    return res.status(403).json({
      message: "Accesso negato"
    });
  }

  const users = readJSON(usersFile);

  const pendingBrands = users
    .filter(user => user.role === "brand" && user.approved !== true)
    .map(user => ({
      id: user.id,
      email: user.email,
      role: user.role,
      approved: user.approved,
      createdAt: user.createdAt
    }));

  res.json(pendingBrands);
});
/* APPROVA BRAND */
app.post("/approve-brand", (req, res) => {
  const { password, email } = req.body;

  if (password !== "STITCHVALEADMIN") {
    return res.status(403).json({
      message: "Accesso negato"
    });
  }

  const users = readJSON(usersFile);
  const user = users.find(u => u.email === email);

  if (!user) {
    return res.status(404).json({
      message: "Utente non trovato"
    });
  }

  if (user.role !== "brand") {
    return res.status(400).json({
      message: "Questo utente non è un brand"
    });
  }

  user.approved = true;
  user.approvedAt = new Date().toISOString();

  writeJSON(usersFile, users);

  res.json({
    message: "Brand approvato",
    email: user.email
  });
});

/* STRIPE CHECKOUT */
app.post("/create-checkout-session", async (req, res) => {
  try {
    const { name, price } = req.body;

    if (!name || !price) {
      return res.status(400).json({
        error: "Nome e prezzo obbligatori"
      });
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
      success_url: "https://www.stitchvale.com/success.html",
      cancel_url: "https://www.stitchvale.com/cancel.html"
    });

    res.json({
      url: session.url
    });
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log("Server avviato su porta " + PORT);
});


