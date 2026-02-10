const express   = require('express');
const { engine } = require('express-handlebars');
const path      = require('path');
const bcrypt    = require('bcryptjs');
const session   = require('express-session');
const multer    = require('multer');

const app = express();

// ——————————————————————————
// MULTER CONFIG (CV Upload)
// ——————————————————————————

// Stockage CV dans public/cvs/
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/cvs/'); // dossier cvs
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + req.session.user?.id + '-' + file.originalname);
  }
});

const uploadCV = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Seulement PDF acceptés'), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB max
});

// ——————————————————————————
// VIEW ENGINE
// ——————————————————————————

app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

app.engine('hbs', engine({
  extname: '.hbs',
  defaultLayout: 'main'
}));

// ——————————————————————————
// MIDDLEWARES
// ——————————————————————————

// Middleware: vérifier si guide validé
const checkGuideValidated = (req, res, next) => {
  if (req.session.user?.role !== 'GUIDE') return res.redirect("/login");

  db.query(
    "SELECT cv_approved FROM guides WHERE id_utilisateur = ?",
    [req.session.user.id],
    (err, rows) => {
      if (err || rows.length === 0 || !rows[0].cv_approved) {
        return res.status(403).render("guide/non-valide", {
          user: req.session.user,
          message: "Votre CV doit être approuvé par l'administrateur avant de créer des plans"
        });
      }
      next();
    }
  );
};

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'insideTunisiaSecret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 }
}));

// Connexion base via config/db.js (tu l’as cool dis!)
const db = require('./config/db');

// ——————————————————————————
// ROUTE PRINCIPALE: accueil
// ——————————————————————————

app.get("/", (req, res) => {
  db.query("SELECT * FROM gouvernorats", (err, rows) => {
    if (err) {
      console.error("Erreur DB:", err);
      return res.status(500).send("Erreur serveur");
    }
    res.render("accueil", { gouvernorats: rows });
  });
});

// ——————————————————————————
// INSCRIPTION TOURISTE
// ——————————————————————————

app.get("/register", (req, res) => {
  res.render("auth/register");
});

app.post("/register", (req, res) => {
  const { nom_complet, email, mot_de_passe, telephone, nationalite, role } = req.body;

  if (!email || !mot_de_passe) {
    return res.render("auth/register", { error: "Email et mot de passe requis" });
  }

  const hashedPassword = bcrypt.hashSync(mot_de_passe, 10);

  db.query(
    "INSERT INTO utilisateurs (nom_complet, email, mot_de_passe, role, est_actif) VALUES (?, ?, ?, ?, 1)",
    [nom_complet, email, hashedPassword, role],
    (err, result) => {
      if (err) {
        console.error("ERREUR utilisateurs:", err);
        return res.status(500).send("Erreur serveur (inscription)");
      }

      const id_utilisateur = result.insertId;

      if (role === "TOURISTE") {
        db.query(
          "INSERT INTO touristes (id_utilisateur, nationalite, telephone) VALUES (?, ?, ?)",
          [id_utilisateur, nationalite || null, telephone || null],
          (err2) => {
            if (err2) {
              console.error("ERREUR touristes:", err2);
              return res.status(500).send("Erreur Base touristes");
            }
            res.redirect("/login");
          }
        );
      } else if (role === "GUIDE") {
        db.query(
          "INSERT INTO guides (id_utilisateur, cv, statut) VALUES (?, NULL, 'ACTIF')",
          [id_utilisateur],
          (err2) => {
            if (err2) {
              console.error("ERREUR guides:", err2);
              return res.status(500).send("Erreur Base guides");
            }
            res.redirect("/login");
          }
        );
      }
    }
  );
});

// ——————————————————————————
// LOGIN
// ——————————————————————————

app.get("/login", (req, res) => {
  res.render("auth/login");
});

app.post("/login", (req, res) => {
  const { email, mot_de_passe } = req.body;

  db.query(
    "SELECT * FROM utilisateurs WHERE email = ?",
    [email],
    (err, rows) => {
      if (err) {
        console.error("ERREUR login:", err);
        return res.status(500).send("Erreur serveur");
      }

      if (!rows || rows.length !== 1) {
        return res.render("auth/login", { error: "Email ou mot de passe incorrect" });
      }

      const user = rows[0];
      if (!bcrypt.compareSync(mot_de_passe, user.mot_de_passe)) {
        return res.render("auth/login", { error: "Mot de passe incorrect" });
      }

      req.session.user = user;

      if      (user.role === 'TOURISTE') { res.redirect("/"); }
      else if (user.role === 'GUIDE')    { res.redirect("/guide/dashboard");  }
      else                               { res.redirect("/admin/dashboard");  }
    }
  );
});

// ———————————————————
// DASHBOARD TOURISTE
// ———————————————————

app.get("/touriste/dashboard", (req, res) => {
  if (!req.session.user || req.session.user.role !== "TOURISTE") {
    return res.redirect("/login");
  }

  db.query("SELECT * FROM plans_touristiques", (err, plans) => {
    if (err) {
      console.error("ERREUR plans_touristiques:", err);
      return res.status(500).send("Erreur serveur");
    }

    res.render("touriste/dashboard", {
      user: req.session.user,
      plans
    });
  });
});

// ———————————————————
// GUIDE DASHBOARD
// ———————————————————

// Dashboard Guide - Liste ses plans + stats
app.get("/guide/dashboard", (req, res) => {
  // Vérifier que c'est un guide connecté
  if (!req.session.user || req.session.user.role !== "GUIDE") {
    return res.redirect("/login");
  }

  const id_guide = req.session.user.id;

  db.query(`
    SELECT COUNT(*) as nb_plans 
    FROM plans_touristiques 
    WHERE id_guide = ?
  `, [id_guide], (err1, stats) => {
    if (err1) {
      console.error("Erreur stats guide:", err1);
      return res.status(500).send("Erreur serveur");
    }

    db.query(`
      SELECT p.*, g.nom_complet as nom_guide
      FROM plans_touristiques p 
      JOIN utilisateurs g ON p.id_guide = g.id 
      WHERE p.id_guide = ?
      ORDER BY p.date_debut DESC 
      LIMIT 5
    `, [id_guide], (err2, plans) => {
      if (err2) {
        console.error("Erreur plans guide:", err2);
        return res.status(500).send("Erreur serveur");
      }

      res.render("guide/dashboard", {
        user: req.session.user,
        nb_plans: stats[0].nb_plans,
        plans: plans
      });
    });
  });
});

// Guide plans list
app.get("/guide/plans", checkGuideValidated, (req, res) => {
  const id_guide = req.session.user.id;

  db.query(
    "SELECT * FROM plans_touristiques WHERE id_guide = ? ORDER BY date_debut DESC",
    [id_guide],
    (err, plans) => {
      if (err) {
        console.error("Erreur plans_touristiques:", err);
        return res.status(500).send("Erreur serveur");
      }

      res.render("guide/plans", {
        user: req.session.user,
        plans
      });
    }
  );
});

// Create new plan form
app.get("/guide/plans/new", checkGuideValidated, (req, res) => {
  res.render("guide/create-plan", {
    user: req.session.user
  });
});

// Create new plan
app.post("/guide/plans", checkGuideValidated, (req, res) => {
  const { titre, description, date_debut, date_fin, prix } = req.body;
  const id_guide = req.session.user.id;

  db.query(
    "INSERT INTO plans_touristiques (id_guide, titre, description, date_debut, date_fin, prix) VALUES (?, ?, ?, ?, ?, ?)",
    [id_guide, titre, description, date_debut, date_fin, prix],
    (err, result) => {
      if (err) {
        console.error("ERREUR création plan:", err);
        return res.status(500).send("Erreur création plan");
      }
      res.redirect("/guide/plans");
    }
  );
});

// Profil Guide - Modifier infos + CV + statut
app.get("/guide/profile", (req, res) => {
  if (!req.session.user || req.session.user.role !== "GUIDE") {
    return res.redirect("/login");
  }

  const id_guide = req.session.user.id;

  // Récupérer infos guide + CV + abonnement
  db.query(`
    SELECT u.*, g.cv, g.cv_approved, g.abonnement_actif, g.abonnement_fin
    FROM utilisateurs u 
    LEFT JOIN guides g ON u.id = g.id_utilisateur
    WHERE u.id = ?
  `, [id_guide], (err, rows) => {
    if (err) {
      console.error("Erreur profil guide:", err);
      return res.status(500).send("Erreur serveur");
    }

    if (rows.length === 0) {
      return res.status(404).send("Profil introuvable");
    }

    const guide = rows[0];

    res.render("guide/profile", {
      user: req.session.user,
      guide: guide
    });
  });
});

// Route UPDATE profil (bonus)
app.post("/guide/profile/update", (req, res) => {
  if (!req.session.user || req.session.user.role !== "GUIDE") {
    return res.redirect("/login");
  }

  const { telephone, bio } = req.body;
  const id_guide = req.session.user.id;

  db.query(
    "UPDATE utilisateurs SET telephone = ?, bio = ? WHERE id = ?",
    [telephone, bio || null, id_guide],
    (err) => {
      if (err) {
        console.error("Erreur update profil:", err);
        return res.status(500).send("Erreur serveur");
      }

      res.redirect("/guide/profile");
    }
  );
});

// Guide subscription page
app.get("/guide/abonnement", (req, res) => {
  if (!req.session.user || req.session.user.role !== "GUIDE") {
    return res.redirect("/login");
  }

  // Get guide's subscription info
  db.query(
    "SELECT abonnement_actif, abonnement_fin FROM guides WHERE id_utilisateur = ?",
    [req.session.user.id],
    (err, result) => {
      if (err) {
        console.error("ERREUR abonnement:", err);
        return res.status(500).send("Erreur serveur");
      }

      const guideData = result[0] || {};
      const userWithSub = {
        ...req.session.user,
        abonnement_actif: guideData.abonnement_actif || 0,
        abonnement_fin: guideData.abonnement_fin
      };

      res.render("guide/abonnement", {
        user: userWithSub
      });
    }
  );
});

// Guide activate subscription (simulation)
app.post("/guide/abonnement/activer", (req, res) => {
  if (!req.session.user || req.session.user.role !== 'GUIDE') return res.status(403);

  // Ici tu intègres Stripe/PayPal
  const id_guide = req.session.user.id;

  db.query(
    "UPDATE guides SET abonnement_actif = 1, abonnement_fin = DATE_ADD(NOW(), INTERVAL 1 MONTH) WHERE id_utilisateur = ?",
    [id_guide],
    (err) => {
      if (err) {
        console.error("ERREUR activation abonnement:", err);
        return res.status(500).send("Erreur activation abonnement");
      }
      res.redirect("/guide/abonnement");
    }
  );
});

// ———————————————————
// ADMIN DASHBOARD
// ———————————————————

app.get("/admin/dashboard", (req, res) => {
  if (!req.session.user || req.session.user.role !== "ADMIN") {
    return res.redirect("/login");
  }

  // Get statistics
  db.query(`
    SELECT 
      (SELECT COUNT(*) FROM touristes) as touristes,
      (SELECT COUNT(*) FROM guides) as guides,
      (SELECT COUNT(*) FROM plans_touristiques) as plans,
      (SELECT COUNT(*) FROM guides WHERE cv_approved = 0) as cvAttente
  `, (err, stats) => {
    if (err) {
      console.error("ERREUR stats admin:", err);
      stats = [{ touristes: 0, guides: 0, plans: 0, cvAttente: 0 }];
    }

    res.render("admin/dashboard", {
      user: req.session.user,
      stats: stats[0]
    });
  });
});

// Admin liste les CV en attente
app.get("/admin/cv-attente", (req, res) => {
  if (!req.session.user || req.session.user.role !== 'ADMIN') {
    return res.redirect("/login");
  }

  db.query(`
    SELECT u.nom_complet, g.id_utilisateur, g.cv 
    FROM guides g 
    JOIN utilisateurs u ON g.id_utilisateur = u.id 
    WHERE g.cv_approved = 0
  `, (err, cvs) => {
    if (err) {
      console.error("ERREUR cv attente:", err);
      cvs = [];
    }
    res.render("admin/cv-attente", { 
      user: req.session.user,
      cvs 
    });
  });
});

// Admin approuve CV
app.post("/admin/cv/:id/approve", (req, res) => {
  if (!req.session.user || req.session.user.role !== 'ADMIN') return res.status(403).send("Accès refusé");

  const id_guide = req.params.id;

  db.query(
    "UPDATE guides SET cv_approved = 1, date_validation = NOW() WHERE id_utilisateur = ?",
    [id_guide],
    (err) => {
      if (err) {
        console.error("ERREUR validation CV:", err);
        return res.status(500).send("Erreur validation");
      }

      // Notification au guide
      db.query(
        "INSERT INTO notifications (id_utilisateur, type, contenu) VALUES (?, 'CV', 'Votre CV a été approuvé!')",
        [id_guide],
        (notifErr) => {
          if (notifErr) console.error("ERREUR notification:", notifErr);
        }
      );

      res.redirect("/admin/cv-attente");
    }
  );
});

// ———————————————————
// SERVER (Port)
// ———————————————————

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
