// ─────────────────────────────────────────────
// server.js — PédagoGen Backend
// Node.js + Express + PostgreSQL + JWT + Resend
// ─────────────────────────────────────────────
const express    = require("express");
const cors       = require("cors");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const { Pool }   = require("pg");
const { Resend } = require("resend");
const Anthropic  = require("@anthropic-ai/sdk");

const app    = express();
const pool   = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const resend = new Resend(process.env.RESEND_API_KEY);
const ai     = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

app.use(cors({ origin: process.env.FRONTEND_URL || "*" }));
app.use(express.json({ limit: "20mb" }));

// ── JWT middleware ────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Non authentifié" });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Token invalide" }); }
};
const adminOnly = (req, res, next) =>
  req.user.role === "admin" ? next() : res.status(403).json({ error: "Accès refusé" });
const gestOnly  = (req, res, next) =>
  ["admin","gestionnaire"].includes(req.user.role) ? next() : res.status(403).json({ error: "Accès refusé" });

// ════════════════════════════════════════════
// INITIALISATION BASE DE DONNÉES
// ════════════════════════════════════════════
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          SERIAL PRIMARY KEY,
      role        TEXT NOT NULL DEFAULT 'client',
      nom         TEXT NOT NULL,
      prenom      TEXT NOT NULL,
      email       TEXT UNIQUE NOT NULL,
      password    TEXT NOT NULL,
      mobile      TEXT DEFAULT '',
      entreprise  TEXT DEFAULT '',
      siren       TEXT DEFAULT '',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS twofa (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
      code       TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS demands (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
      titre       TEXT NOT NULL,
      statut      TEXT NOT NULL DEFAULT 'Déposé',
      public      TEXT,
      duree       TEXT,
      objectif    TEXT,
      ton         TEXT,
      result      JSONB,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS documents (
      id         SERIAL PRIMARY KEY,
      demand_id  INTEGER REFERENCES demands(id) ON DELETE CASCADE,
      nom        TEXT NOT NULL,
      file_type  TEXT,
      taille     INTEGER,
      text_content TEXT,
      data_url   TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS notes (
      id         SERIAL PRIMARY KEY,
      demand_id  INTEGER REFERENCES demands(id) ON DELETE CASCADE,
      auteur_id  INTEGER REFERENCES users(id),
      auteur_role TEXT,
      texte      TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Créer admin par défaut si absent
  const existing = await pool.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash("admin123", 10);
    await pool.query(
      "INSERT INTO users (role,nom,prenom,email,password) VALUES ($1,$2,$3,$4,$5)",
      ["admin","Admin","Super","ebrembilla@gmail.com", hash]
    );
    // Gestionnaire démo
    const h2 = await bcrypt.hash("gest123", 10);
    await pool.query(
      "INSERT INTO users (role,nom,prenom,email,password) VALUES ($1,$2,$3,$4,$5)",
      ["gestionnaire","Martin","Léa","lea@pedagogen.fr", h2]
    );
    // Client démo
    const h3 = await bcrypt.hash("client123", 10);
    await pool.query(
      "INSERT INTO users (role,nom,prenom,email,password,mobile,entreprise,siren) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
      ["client","Dupont","Marc","marc@client.fr", h3,"0612345678","Dupont SA","123456789"]
    );
    console.log("✅ Comptes démo créés");
  }
  console.log("✅ Base de données initialisée");
}

// =================================$
// AUTH
// =================================$


app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (!rows.length) return res.status(401).json({ error: "Email ou mot de passe incorrect" });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Email ou mot de passe incorrect" });
    const token = jwt.sign(
      { id: user.id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );
    const { password: _, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erreur serveur" });
  }
});




// ════════════════════════════════════════════
// USERS
// ════════════════════════════════════════════

// GET /api/users
app.get("/api/users", auth, adminOnly, async (req, res) => {
  const { rows } = await pool.query("SELECT id,role,nom,prenom,email,mobile,entreprise,siren,created_at FROM users ORDER BY created_at DESC");
  res.json(rows);
});

// POST /api/users
app.post("/api/users", auth, adminOnly, async (req, res) => {
  const { role,nom,prenom,email,password,mobile,entreprise,siren } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "INSERT INTO users (role,nom,prenom,email,password,mobile,entreprise,siren) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,role,nom,prenom,email,mobile,entreprise,siren",
      [role,nom,prenom,email,hash,mobile||"",entreprise||"",siren||""]
    );
    res.json(rows[0]);
  } catch (e) {
    if (e.code === "23505") return res.status(400).json({ error: "Email déjà utilisé" });
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// PUT /api/users/:id
app.put("/api/users/:id", auth, async (req, res) => {
  // Un user peut modifier son propre profil ; un admin peut tout modifier
  if (req.user.role !== "admin" && req.user.id !== parseInt(req.params.id))
    return res.status(403).json({ error: "Accès refusé" });
  const { nom,prenom,email,password,mobile,entreprise,siren } = req.body;
  try {
    let query, params;
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      query  = "UPDATE users SET nom=$1,prenom=$2,email=$3,password=$4,mobile=$5,entreprise=$6,siren=$7 WHERE id=$8 RETURNING id,role,nom,prenom,email,mobile,entreprise,siren";
      params = [nom,prenom,email,hash,mobile||"",entreprise||"",siren||"",req.params.id];
    } else {
      query  = "UPDATE users SET nom=$1,prenom=$2,email=$3,mobile=$4,entreprise=$5,siren=$6 WHERE id=$7 RETURNING id,role,nom,prenom,email,mobile,entreprise,siren";
      params = [nom,prenom,email,mobile||"",entreprise||"",siren||"",req.params.id];
    }
    const { rows } = await pool.query(query, params);
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// DELETE /api/users/:id
app.delete("/api/users/:id", auth, adminOnly, async (req, res) => {
  await pool.query("DELETE FROM users WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

// ════════════════════════════════════════════
// DEMANDS
// ════════════════════════════════════════════

// GET /api/demands
app.get("/api/demands", auth, async (req, res) => {
  let query, params;
  if (req.user.role === "client") {
    query  = "SELECT d.*,u.nom,u.prenom,u.entreprise FROM demands d JOIN users u ON d.client_id=u.id WHERE d.client_id=$1 ORDER BY d.created_at DESC";
    params = [req.user.id];
  } else {
    query  = "SELECT d.*,u.nom,u.prenom,u.entreprise FROM demands d JOIN users u ON d.client_id=u.id ORDER BY d.created_at DESC";
    params = [];
  }
  const { rows } = await pool.query(query, params);
  // Enrichir avec docs et notes
  const enriched = await Promise.all(rows.map(async d => {
    const docs  = await pool.query("SELECT id,nom,file_type,taille,text_content,data_url FROM documents WHERE demand_id=$1", [d.id]);
    const notes = await pool.query("SELECT n.*,u.nom,u.prenom FROM notes n JOIN users u ON n.auteur_id=u.id WHERE n.demand_id=$1 ORDER BY n.created_at ASC", [d.id]);
    return {
      ...d,
      client: d.entreprise || `${d.prenom} ${d.nom}`,
      date: new Date(d.created_at).toLocaleDateString("fr-FR"),
      docs:  docs.rows.map(doc => ({ name:doc.nom, fileType:doc.file_type, size:doc.taille, text:doc.text_content, dataUrl:doc.data_url })),
      notes: notes.rows.map(n => ({ id:n.id, text:n.texte, author:n.auteur_role==="client"?"Client":"Équipe", date:new Date(n.created_at).toLocaleString("fr-FR") })),
    };
  }));
  res.json(enriched);
});

// POST /api/demands
app.post("/api/demands", auth, async (req, res) => {
  const { titre,public:pub,duree,objectif,ton,docs } = req.body;
  try {
    const { rows } = await pool.query(
      "INSERT INTO demands (client_id,titre,public,duree,objectif,ton,statut) VALUES ($1,$2,$3,$4,$5,$6,'Déposé') RETURNING *",
      [req.user.id,titre,pub,duree,objectif,ton]
    );
    const demand = rows[0];
    // Insérer les documents
    if (docs?.length) {
      for (const doc of docs) {
        await pool.query(
          "INSERT INTO documents (demand_id,nom,file_type,taille,text_content,data_url) VALUES ($1,$2,$3,$4,$5,$6)",
          [demand.id, doc.name, doc.fileType, doc.size, (doc.text||"").replace(/\x00/g,""), (doc.dataUrl||"").replace(/\x00/g,"")]
        );
      }
    }
    res.json({ ...demand, date: new Date(demand.created_at).toLocaleDateString("fr-FR"), docs:docs||[], notes:[] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// PUT /api/demands/:id/statut
app.put("/api/demands/:id/statut", auth, async (req, res) => {
  const { statut } = req.body;
  // Seul le client peut valider, seul le gestionnaire peut avancer les autres statuts
  if (statut === "Validé" && req.user.role !== "client") return res.status(403).json({ error: "Seul le client peut valider" });
  if (statut !== "Validé" && req.user.role === "client")  return res.status(403).json({ error: "Action non autorisée" });
  await pool.query("UPDATE demands SET statut=$1 WHERE id=$2", [statut, req.params.id]);
  res.json({ ok: true });
});

// PUT /api/demands/:id/result
app.put("/api/demands/:id/result", auth, gestOnly, async (req, res) => {
  const { result, statut } = req.body;
  // Vérifier que la demande n'est pas verrouillée
  const { rows } = await pool.query("SELECT statut FROM demands WHERE id=$1", [req.params.id]);
  if (rows[0]?.statut === "Validé") return res.status(403).json({ error: "Matrice verrouillée" });
  await pool.query("UPDATE demands SET result=$1, statut=COALESCE($2,statut) WHERE id=$3", [JSON.stringify(result), statut||null, req.params.id]);
  res.json({ ok: true });
});

// PUT /api/demands/:id/result (client peut aussi modifier si pas validé)
app.put("/api/demands/:id/result-client", auth, async (req, res) => {
  const { result } = req.body;
  const { rows } = await pool.query("SELECT statut,client_id FROM demands WHERE id=$1", [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: "Demande introuvable" });
  if (rows[0].statut === "Validé") return res.status(403).json({ error: "Matrice verrouillée" });
  if (req.user.role === "client" && rows[0].client_id !== req.user.id) return res.status(403).json({ error: "Accès refusé" });
  await pool.query("UPDATE demands SET result=$1 WHERE id=$2", [JSON.stringify(result), req.params.id]);
  res.json({ ok: true });
});

// ════════════════════════════════════════════
// NOTES
// ════════════════════════════════════════════

// POST /api/demands/:id/notes
app.post("/api/demands/:id/notes", auth, async (req, res) => {
  const { texte } = req.body;
  const auteurRole = req.user.role === "client" ? "client" : "gestionnaire";
  const { rows } = await pool.query(
    "INSERT INTO notes (demand_id,auteur_id,auteur_role,texte) VALUES ($1,$2,$3,$4) RETURNING *",
    [req.params.id, req.user.id, auteurRole, texte]
  );
  res.json({
    id:     rows[0].id,
    text:   rows[0].texte,
    author: auteurRole === "client" ? "Client" : "Équipe",
    date:   new Date(rows[0].created_at).toLocaleString("fr-FR")
  });
});

// ════════════════════════════════════════════
// GÉNÉRATION IA
// ════════════════════════════════════════════

// POST /api/demands/:id/generate
app.post("/api/demands/:id/generate", auth, gestOnly, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM demands WHERE id=$1", [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: "Demande introuvable" });
  const demand = rows[0];
  const docs   = await pool.query("SELECT text_content FROM documents WHERE demand_id=$1", [demand.id]);
  const src    = docs.rows.map(d=>d.text_content).filter(Boolean).join("\n").slice(0,1200);

  try {
    const msg = await ai.messages.create({
      model: "claude-sonnet-4-20250514",
      max_tokens: 2000,
      messages: [{
        role: "user",
        content: `Expert ingénierie pédagogique. Génère une matrice pédagogique CONCISE.
Formation:${demand.titre}|Public:${demand.public}|Durée:${demand.duree}h|Ton:${demand.ton}
Objectif:${demand.objectif}
${src ? `Source:\n${src}` : ""}
JSON valide UNIQUEMENT sans markdown. Max 3 obj généraux, 5 obj péda, 4 modules.
{"objectifs_generaux":[{"titre":"","description":""}],"objectifs_pedagogiques":[{"code":"OP1","intitule":"","niveau_bloom":"","modalite":""}],"programme":[{"module":"","duree":"","contenu":[""],"methodes":""}]}`
      }]
    });

    const raw   = msg.content.map(b=>b.text||"").join("").trim();
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) throw new Error("Pas de JSON dans la réponse");
    const result = JSON.parse(match[0]);

    await pool.query("UPDATE demands SET result=$1, statut='Généré' WHERE id=$2", [JSON.stringify(result), demand.id]);
    res.json({ result, statut: "Généré" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: `Erreur génération : ${e.message}` });
  }
});

// ════════════════════════════════════════════
// HEALTH CHECK
// ════════════════════════════════════════════
app.get("/api/health", (_, res) => res.json({ ok: true, ts: new Date() }));

// ════════════════════════════════════════════
// DÉMARRAGE
// ════════════════════════════════════════════
const PORT = process.env.PORT || 3001;
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 PédagoGen API sur le port ${PORT}`));
}).catch(e => { console.error("Erreur DB:", e); process.exit(1); });
