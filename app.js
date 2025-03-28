/**
 * Let's create an authentication server that will obtain data from a login form 
 */
// We have used express, cors, and fs before:
const express = require('express');
const cors = require('cors');
const fs = require('fs');
require('dotenv').config();

// for authentication end encryption, we will use JWT and crypto: 
// Learn more about JWT here:
// https://auth0.com/docs/secure/tokens/json-web-tokens and https://www.npmjs.com/package/jsonwebtoken
const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');

// Let's declare the app, port number, and cors policy:
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors()); // allow all requests.
app.use(express.json()); // define middleware to parse json

// This is our "database" for this exercise. A local json file. In your project, you should connect with the database.
const filepath = './users.json';

// load users on startup
let users = loadUsers();

console.log(PORT, process.env.JWT_SECRET_KEY);
// Function to hash a password. It uses the original passsword string and a "salt". Here's a good article:
// https://medium.com/@amirakhaled2027/understanding-salt-in-node-js-a-comprehensive-guide-to-secure-password-hashing-54cc60890b4a 
function hashPassword(password, salt) {
    // https://www.geeksforgeeks.org/node-js-crypto-pbkdf2sync-method/
    return crypto.pbkdf2Sync(password, salt, 10, 64, 'sha512').toString('hex');
}

const verifyToken = (req, res, next) => { 
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(403).json({ error: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1]; // Extract the token part

    try { 
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY); 
        req.user = decoded; 
        next(); // Proceed to the next middleware
    } catch (err) { 
        return res.status(401).json({ error: "Invalid token" }); 
    } 
};

/************************************************************************
 * Our  Routes                                                          *
 ************************************************************************/

// Just a random protected route if you with to test a different enpoint:
app.get("/protected", verifyToken, (req, res) => { 
    const { user } = req; 
    res.json({ msg: `Welcome ${user.email}` }); 
});


app.get('/', verifyToken, (req, res) => {
    console.log("User data from token:", req.user);
    res.json(req.user);
});

// Let's define our registration route:
app.post('/register', async (req, res) => {
    // If we know the way the frontend is sending the body, we can declare an object to receive the data accordingly:
    const {email, password} = req.body;
    // if user exists, early return.
    if(users[email]) return res.status(400).json({error: "User already exists!"});
    
    // else try to save to "database"
    try {
        const salt = crypto.randomBytes(16).toString('hex');
        const hashedPassword = hashPassword(password, salt);
        const newUser = { salt, hashedPassword };

        users[email] = newUser;
        saveUsers(users);

        res.status(201).json({message: "User registered succesfully!"});
    } catch {
        res.status(500).send("fail");
    }
})

app.post('/login', async (req, res) => {
    // just simulating, we already got the user by req.body.email from database
    const {email, password } = req.body;
    const user = users[email];

    // If not found, early return.
    if (!user) return res.status(400).json({ error: "User not found" });

    // else try to authenticate
    try {
        const hashedPassword = hashPassword(password, user.salt);
        if (hashedPassword !== user.hashedPassword) {
            return res.status(401).json({ error: "Invalid credentials" });
        } 
    } catch {
        res.status(500).send()
    }
    const token = jwt.sign({ email },  
        process.env.JWT_SECRET_KEY, { 
            expiresIn: 86400 
        }); 
    res.json({ email, token, message: "Login successful" });
})


/************************************************************************
 * Let's declare our functions down here and keep the logic up top.     *
 ************************************************************************/
function saveUsers(users) {
    try {
        fs.writeFileSync(filepath, JSON.stringify(users, null, 2), 'utf8');
    } catch (err) {
        console.error("Error saving users file:", err);
    }
}

// Function to load users from JSON file.
function loadUsers() {
    try {
        if (!fs.existsSync(filepath)) {
            // if the file doesn't exist, create a new file with an empty object:
            fs.writeFileSync(filepath, JSON.stringify({}), 'utf8');
        }

        // read the file contents, parsed:
        return JSON.parse(fs.readFileSync(filepath, 'utf8'));

    } catch (err) {
        console.error("Error reading users file:", err);
        return {};
    }
}

// Start the server to listen for HTTP events on port number ${PORT}:
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}'`);
})
