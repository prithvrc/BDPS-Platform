const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const db = new Database("database.db");

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: false,
  })
);

const multer = require("multer");
const fs = require("fs");

if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB limit
  fileFilter: function (req, file, cb) {
    const allowed = ["image/", "video/"];
    if (allowed.some(type => file.mimetype.startsWith(type))) {
      cb(null, true);
    } else {
      cb(new Error("Only images and videos allowed"));
    }
  }
});

app.use("/uploads", express.static("uploads"));


// Create Tables
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  email TEXT,
  password_hash TEXT,
  role TEXT DEFAULT 'user',
  status TEXT DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  content TEXT,
  media TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();try {
  db.prepare("ALTER TABLE posts ADD COLUMN media TEXT").run();
} catch (err) {
  // column already exists
}



db.prepare(`
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  content TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();

// Middleware
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.redirect("/feed");
  next();
}

// Routes

app.get("/", (req, res) => {
  res.redirect("/login");
});

// Signup
app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get().count;
  const role = userCount === 0 ? "admin" : "user";

  db.prepare(`
    INSERT INTO users (username, email, password_hash, role)
    VALUES (?, ?, ?, ?)
  `).run(username, email, hashed, role);

  res.redirect("/login");
});

// Login
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  if (!user) return res.send("User not found");

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.send("Wrong password");

  if (user.status !== "approved" && user.role !== "admin")
    return res.send("Waiting for admin approval.");

  req.session.user = user;
  res.redirect("/feed");
});

// Feed
app.get("/feed", requireLogin, (req, res) => {
  const posts = db.prepare(`
    SELECT posts.*, users.username
    FROM posts
    JOIN users ON posts.user_id = users.id
    ORDER BY posts.created_at DESC
  `).all();

  res.render("feed", { user: req.session.user, posts });
});

app.post("/post", requireLogin, upload.single("media"), (req, res) => {
  const { content } = req.body;
  const mediaPath = req.file ? req.file.filename : null;

  db.prepare(`
    INSERT INTO posts (user_id, content, media)
    VALUES (?, ?, ?)
  `).run(req.session.user.id, content, mediaPath);

  res.redirect("/feed");
});


// Delete Post
app.post("/delete/:id", requireLogin, (req, res) => {
  const post = db.prepare("SELECT * FROM posts WHERE id = ?")
    .get(req.params.id);

  if (!post) return res.send("Post not found");

  // Security check: only owner can delete
  if (post.user_id !== req.session.user.id) {
    return res.send("Not authorized");
  }

  db.prepare("DELETE FROM posts WHERE id = ?")
    .run(req.params.id);

  res.redirect("back");
});


// Own profile
app.get("/profile", requireLogin, (req, res) => {
  const profileUser = req.session.user;

  const posts = db.prepare(`
    SELECT posts.*, users.username
    FROM posts
    JOIN users ON posts.user_id = users.id
    WHERE users.id = ?
    ORDER BY posts.created_at DESC
  `).all(profileUser.id);

  res.render("profile", {
    user: req.session.user,
    profileUser,
    posts
  });
});

// Other user profile
app.get("/profile/:id", requireLogin, (req, res) => {
  const profileUser = db.prepare(
    "SELECT id, username FROM users WHERE id = ?"
  ).get(req.params.id);

  if (!profileUser) return res.send("User not found");

  const posts = db.prepare(`
    SELECT posts.*, users.username
    FROM posts
    JOIN users ON posts.user_id = users.id
    WHERE users.id = ?
    ORDER BY posts.created_at DESC
  `).all(profileUser.id);

  res.render("profile", {
    user: req.session.user,
    profileUser,
    posts
  });
});



// Admin
app.get("/admin", requireLogin, requireAdmin, (req, res) => {
  const users = db.prepare("SELECT * FROM users WHERE role = 'user'").all();
  res.render("admin", { users });
});

app.post("/approve/:id", requireLogin, requireAdmin, (req, res) => {
  db.prepare("UPDATE users SET status = 'approved' WHERE id = ?")
    .run(req.params.id);
  res.redirect("/admin");
});

app.post("/reject/:id", requireLogin, requireAdmin, (req, res) => {
  db.prepare("UPDATE users SET status = 'rejected' WHERE id = ?")
    .run(req.params.id);
  res.redirect("/admin");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});

