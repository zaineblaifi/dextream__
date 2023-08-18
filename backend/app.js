const express = require('express')
const multer = require('multer');
const session = require('express-session');
const app = express();
//const fs = require('fs');
const { body, validationResult } = require('express-validator');
//const https=require('https');
//const path=require('path');
/*const sslServer=https.createServer({
    key: fs.readFileSync(path.join(__dirname,'./cert/key.pem')), //私钥文件路径
    cert: fs.readFileSync(path.join(__dirname, './cert/cert.pem'))//证书文件路径
}, app)*/

const cors=require('cors');
const jwt=require('jsonwebtoken');
const mysql      = require('mysql');
let bodyParser=require("body-parser");

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'uploads/'); 
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


app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());



app.use(session({
              secret: 'keyboard cat',
              resave: false,
              saveUninitialized: true,
              cookie: { maxAge: 60000 }
            }));





const bcrypt = require('bcrypt');
const saltRounds = 10; 

app.post('/register', [
    body('name').isLength({ min: 4 }).trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('phone').isMobilePhone().optional(),
    body('password').isLength({ min: 8 }),
  ], (req, res) => {
            const checkUserSql = "SELECT * FROM user WHERE email = ?";
            const insertUserSql = "INSERT INTO user (`name`,`email`,`phone`,`password`) VALUES(?)";
        
            const errors = validationResult(req);
        
            if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
            }
        
            connection.query(checkUserSql, [req.body.email], (err, rows) => {
            if (err) {
            return res.json({ Error: "Query Error in server" });
            }
            if (rows.length > 0) {
            return res.json({ Error: "User already registered" });
            }
            bcrypt.hash(req.body.password.toString(), saltRounds, (hashErr, hash) => {
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
            }})
    })});
app.post('/login', [
        body('email').isEmail().normalizeEmail(),
        body('password').isLength({ min: 6 }),
      ], (req, res) => {
        const sql = 'SELECT * FROM user WHERE email=?';
      
        const errors = validationResult(req);
      
        if (!errors.isEmpty()) {
          return res.status(422).json({ errors: errors.array() });
        }
      
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
        res.json(result[0]); 
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.json({ Error: 'Error logging out' });
        }
        res.clearCookie('token'); 
        res.json({ Status: 'Logged out' });
    });
});

const upload = multer({ storage });

app.post('/Enreg_video', upload.single('video'), (req, res) => {
    const userId = req.session.userId;
    const title = req.body.title;
    const description = req.body.description;
    const videoData = req.file.buffer; 

    const insertQuery = 'INSERT INTO videos (user_id, title, description, video_data) VALUES (?, ?, ?, ?)';
    connection.query(insertQuery, [userId, title, description, videoData], (error, results) => {
        if (error) {
            console.error('Erreur lors de l\'insertion dans la base de données : ', error);
            res.status(500).json({ message: 'Erreur lors de l\'insertion dans la base de données.' });
        } else {
            console.log('Vidéo enregistrée dans la base de données.');
            res.status(200).json({ message: 'Vidéo enregistrée avec succès.' });
        }
    });
});


  
  
  

app.listen(8080);