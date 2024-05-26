const express = require('express')
const path = require('path')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const initializeDatabase = () => {
  const db = new sqlite3.Database('./users.db')
  //Initialising a database which contains inf of user like id,username and password.
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
    name TEXT
    )`)
  })

  db.close()
}

initializeDatabase()
//sign up

const app = express()
app.use(express.json())

app.post('/signup', async (req, res) => {
  const {username, password, name} = req.body
  const db = new sqlite3.Database('./users.db')
  //hashing mean to encrypt the password
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      return res.status(500).send('Error hashing password') //500=error response
    }

    const stmt = db.prepare(
      'INSERT INTO users (username, password) VALUES (?, ?)',
    )
    stmt.run(username, hash, function (err) {
      if (err) {
        return res.status(500).send('Error storing user in database')
      }
      res.status(200).send('User registered successfully')
    })

    stmt.finalize()
  })

  db.close()
})
//login api
//login is for who alraedy signup
const jwt = require('jsonwebtoken') //token is used to verify whether the user is valid or  Invalid

app.post('/login', (req, res) => {
  const {username, password} = req.body
  const db = new sqlite3.Database('./users.db')

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      return res.status(500).send('Error querying database')
    }
    if (!row) {
      return res.status(400).send('User not found')
    }

    bcrypt.compare(password, row.password, (err, isMatch) => {
      if (err) {
        return res.status(500).send('Error comparing passwords')
      }
      if (!isMatch) {
        return res.status(400).send('Incorrect password') //If the password is incorrect
      }

      const token = jwt.sign(
        {id: row.id, username: row.username},
        'secretKey',
        {expiresIn: '1h'},
      )
      res.status(200).json({token})
    })
  })

  db.close()
})
//user details api
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']

  if (!token) {
    return res.status(401).send('Access denied')
  }

  jwt.verify(token, 'secretKey', (err, user) => {
    if (err) {
      return res.status(403).send('Invalid token')
    }

    req.user = user
    next()
  })
}

app.get('/user', authenticateToken, (req, res) => {
  const db = new sqlite3.Database('./users.db')

  db.get(
    'SELECT id, username FROM users WHERE id = ?',
    [req.user.id],
    (err, row) => {
      if (err) {
        return res.status(500).send('Error querying database')
      }
      if (!row) {
        return res.status(404).send('User not found')
      }

      res.status(200).json(row)
    },
  )

  db.close()
})
