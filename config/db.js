// config/db.js
const mysql = require('mysql');

const connection = mysql.createConnection({
  host     : 'localhost',
  user     : 'root',
  password : '',
  database : 'tourisme_tn'
});

connection.connect((err) => {
  if (err) {
    console.error("Erreur connexion MySQL:", err);
    return process.exit(1);
  }
  console.log("✅ Connecté à tourisme_tn");
});

module.exports = connection;
