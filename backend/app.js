const express = require('express')
const multer = require('multer');
const session = require('express-session');
const app = express();
const fs = require('fs');

const cors=require('cors');
const jwt=require('jsonwebtoken');
const mysql      = require('mysql');
let bodyParser=require("body-parser");

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'uploads/'); // Répertoire de stockage des vidéos
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + '-' + file.originalname);
    },
  });

app.use(cors({
    origin:["http://localhost:3000"],
    methods:["POST","GET" ],
    credentials:true
    })
);

const MySQLStore = require('express-mysql-session')(session);

const sessionStore = new MySQLStore({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'dextream'
});

let connection = mysql.createConnection({
              host     : 'localhost',
              user     : 'root',
              password : '',
              database : 'dextream'
            });
 
connection.connect();
 
global.db = connection;

//app.set('port', process.env.PORT || 8080);
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());



app.use(session({
              secret: 'keyboard cat',
              resave: false,
              saveUninitialized: true,
              cookie: { maxAge: 60000 }
            }));





const bcrypt = require('bcrypt');
const salt = 10; 

app.post('/register', (req, res) => {
    const checkUserSql = "SELECT * FROM user WHERE email = ?";
    const insertUserSql = "INSERT INTO user (`name`,`email`,`phone`,`password`) VALUES(?)";

    // Vérification si l'utilisateur est déjà enregistré avec l'adresse e-mail fournie
    connection.query(checkUserSql, [req.body.email], (err, rows) => {
        if (err) {
            return res.json({ Error: "Query Error in server" });
        }
        
        // Si l'utilisateur existe déjà, renvoyer un message d'erreur
        if (rows.length > 0) {
            return res.json({ Error: "User already registered" });
        }

        // Si l'utilisateur n'existe pas, continuer avec l'insertion
        bcrypt.hash(req.body.password.toString(), salt, (hashErr, hash) => {
            if (hashErr) {
                return res.json({ Error: "Error hashing password" });
            } else {
                const values = [
                    req.body.name,
                    req.body.email,
                    req.body.phone,
                    hash
                ];
                connection.query(insertUserSql, [values], (insertErr, result) => {
                    if (insertErr) {
                        return res.json({ Error: "Inserting data Error in server" });
                    }
                    return res.json({ Status: "Success" });
                });
            }
        });
    });
});
app.post('/login',(req, res) => {
    
    const sql = 'SELECT * FROM user WHERE email=?';

    connection.query(sql, [req.body.email], (err, data) => {
        if (err) {
            return res.json({ Error: 'Login error in server' });
        }
        if (data.length === 0) {
            return res.json({ Error: 'No email existed' });
        }
        bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
            if (err) {
                return res.json({ Error: "Password compare error" });
            }
            if (response) {
                const name = data[0].name;
                const token = jwt.sign({ name }, "jwt--secret_key", { expiresIn: '1d' });
                req.session.userId = data[0].id;
                res.cookie('token', token);
                return res.json({ Status: 'Success' });
            } else {
                return res.json({ Error: 'Password not matched' });
            }
        });
    });
});

app.get('/profile', (req, res) => {
    const userId = req.session.userId;
    
    if (!userId) {
        return res.json({ Error: 'Not logged in' });
    }

    const sql = "SELECT name, email, phone FROM user WHERE `id` = ?";
    connection.query(sql, [userId], function (err, result) {
        if (err) {
            return res.json({ Error: 'Error fetching user data' });
        }
        res.json(result[0]); // Assuming you want to return a single user's data
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.json({ Error: 'Error logging out' });
        }
        res.clearCookie('token'); // Clear the JWT cookie
        res.json({ Status: 'Logged out' });
    });
});

const upload = multer({ storage });
app.post('/Enreg_video', upload.single('video'), (req, res) => {
    const videoPath = req.file.path;
    const userId = req.session.userId; // Obtenez l'ID de l'utilisateur connecté
    const title = req.body.title;
    const description = req.body.description;
  
    const insertQuery = 'INSERT INTO videos (user_id, video_path, title, description) VALUES (?, ?, ?, ?)';
    connection.query(insertQuery, [userId, videoPath, title, description], (error, results) => {
      if (error) {
        console.error('Erreur lors de l\'insertion dans la base de données : ', error);
        res.status(500).json({ message: 'Erreur lors de l\'insertion dans la base de données.' });
      } else {
        console.log('Vidéo enregistrée dans la base de données.');
    
        // Supprimer le fichier du serveur une fois qu'il est enregistré
        fs.unlinkSync(videoPath);
    
        res.status(200).json({ message: 'Vidéo téléchargée et enregistrée avec succès.' });
      }
    });
  });
  
  
  

app.listen(8080);