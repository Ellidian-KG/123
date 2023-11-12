const express = require('express')
const config = require("config")
const sqlite3 = require('sqlite3')
const bcrypt = require('bcrypt')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const multer = require('multer');
const fs = require('fs');
const ejs = require('ejs')
const router = express.Router();
const secretkey = config.get('secret')
const path = require('path');
const port = config.get('PORT')
const {
    open
} = require('sqlite')
const app = express()
app.set('view engine', 'ejs');
app.use(cors())
app.use(express.json())
start = async () => {
    open({
        filename: "./db/tilt-db",
        driver: sqlite3.Database
    }).then((db) => {
        try {
            const authMiddleWare = (req, res, next) => {
                const authHeader = req.headers['authorization'];
                const token = authHeader && authHeader.split(' ')[1];
                if (token === null) {
                    return res.status(401).json({
                        message: 'tilt token'
                    })
                }
                jwt.verify(token, secretkey, (err, decoded) => {
                    if (err) {
                        return res.status(403).json({
                            message: 'Error with verify'
                        })
                    }
                    req.username = decoded.username
                    next()
                })
            }
            // app.get('/main', (req, res) => {
            //     res.render("home.ejs", req.query)
            // })

            app.get('/users', async (req, res) => {
                const users = await db.all("SELECT * FROM users")
                return res.json(users)
            })
            app.get('/files', async (req, res) => {
                const files = await db.all("SELECT * FROM files")
                return res.json(files)
            })


            app.post('/registration', async (req, res) => {
                const {
                    username,
                    password
                } = req.body
                if (password.length < 5 || password.length > 12 && username.length < 5 || username.length > 12) {
                    return res.status(400).json({
                        message: "Длина username и пароля должна быть не менее 5 и не больше 12 символов"
                    })
                }
                const hash = await bcrypt.hash(password, 4)
                const result = await db.all(`SELECT * FROM users WHERE username = "${username}"`)
                if (result.length > 0) {
                    return res.status(400).json({
                        message: 'Пользователь с таким username уже существует'
                    });
                } else {
                    await db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function (err) {
                        if (err) {
                            console.error(err);
                            return res.status(500).json({
                                error: 'че то не але'
                            });
                        } else {
                            res.redirect('/main')
                        }
                    });
                }
            })
            app.post('/login', async (req, res) => {
                const user = {
                    username,
                    password
                } = req.body;
                const usernam = await db.all(`SELECT * FROM users WHERE username = "${username}"`)
                const passwor = await db.all(`SELECT * FROM users WHERE password = "${password}"`)
                const hash = await bcrypt.hash(password, 4)
                try {
                    if ((usernam.length > 0) || (user.username === `${username}`) && (passwor.password === `${(hash)}`)) {
                        const token = jwt.sign({
                            username: username
                        }, 'secret_key');
                        return res.redirect('/main')
                    } else {
                        return res.status(400).json({
                            message: "Ошибка логина/пароля"
                        })
                    }
                } catch (e) {
                    console.log(e)
                }
            })
            const storage = multer.diskStorage({
                destination: (req, file, cb) => {
                    cb(null, './uploads');
                },
                filename: (req, file, cb) => {
                    cb(null, file.originalname);
                }
            });

            const upload = multer({
                storage
            });

            app.post('/upload',upload.single('file'), async (req, res) => {
                const file = req.file;

                await db.run('INSERT INTO files (name) VALUES (?)', [file.originalname], function (err) {
                    if (err) {
                        console.error(err);
                       return res.status(500).json({
                            error: 'Внутренняя ошибка сервера'
                        });
                    } else {
                        return res.json({
                            message: 'Файл успешно загружен'
                        });
                    }
                });
            });

            app.get('/download/:filename', async (req, res) => {
                const fileName = req.params.filename;
            
                try {
                    const row = await db.get('SELECT name FROM files WHERE name = ?', [fileName]);
                    if (!row) {
                        return res.status(404).json({ error: 'Файл не найден' });
                    }
            
                    const filePath = path.join(__dirname, 'uploads', row.name);
                    const fileExists = await fs.promises.access(filePath, fs.constants.F_OK)
                        .then(() => true)
                        .catch(() => false);
            
                    if (!fileExists) {
                        return res.status(404).json({ error: 'Файл не найден' });
                    }
            
                    res.download(filePath, row.name);
                } catch (err) {
                    console.error(err);
                    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
                }
            });
            
            app.listen(port, () => {
                console.log("Сервер запущен на: ", port)
            })
        } catch (e) {
            console.log(e)
        }
    })
}

start()