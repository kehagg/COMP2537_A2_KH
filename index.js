
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");
const mongoSanitize = require('express-mongo-sanitize');
const { emit } = require("process");
const expireTime = 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

app.use(mongoSanitize(
    //{replaceWith: '%'}
));

// app.use(
//     mongoSanitize({
//       onSanitize: ({ req, key }) => {
//         console.warn(`This request[${key}] is sanitized`);
//       },
//     }),
//   );

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions2`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        var html = `
        <div><button onclick="window.location.href='/signup'">Sign Up</button></div>
        <div><button onclick="window.location.href='/login'">Log In</button></div>
        `;
    } else {
        var html = `
        <div>Hello, ${req.session.username}!</div>
        <div><button onclick="window.location.href='/members'">Go to Members Area</button></div>
        <div><button onclick="window.location.href='/logout'">Logout</button></div>
        `;
    }
    res.send(html);
});

function isValidSession(req) {
    return req.session.authenticated;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    } else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    return req.session.user_type == 'admin';
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", { error: "Not authorized" });
        return;
    } else {
        next();
    }
}

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({ username: 1, _id: 1 }).toArray();
    res.render('admin', { users: result });
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    } else {
        var images = ['duck.gif', 'frog.gif', 'spongebob.gif'];
        var index = Math.floor(Math.random() * images.length);
        var result = {
            username: req.session.username,
            image: images[index]
        };
        res.render('members', result);
    }
});

app.get('/signupSubmit', (req, res) => {
    var html = `error`;
    var missing = req.query.missing;
    if (missing == 1) {
        var html = `
        Name, email, and password are required.
        <br><br>
        <a href='/signup'>Try Again</a>
    `;
    } else if (missing == 2) {
        var html = `
        Name and email are required.
        <br><br>
        <a href='/signup'>Try Again</a>    
    `;
    } else if (missing == 3) {
        var html = `
        Name and password are required.
        <br><br>
        <a href='/signup'>Try Again</a>    
    `;
    } else if (missing == 4) {
        var html = `
        Email and password are required.
        <br><br>
        <a href='/signup'>Try Again</a>
    `;
    } else if (missing == 5) {
        var html = `
        Name is required.
        <br><br>
        <a href='/signup'>Try Again</a>
    `;
    } else if (missing == 6) {
        var html = `
        Email is required.
        <br><br>
        <a href='/signup'>Try Again</a>
    `;
    } else if (missing == 7) {
        var html = `
        Password is required.
        <br><br>
        <a href='/signup'>Try Again</a>
    `;
    }
    res.send(html);
});

app.get('/signup', (req, res) => {
    res.render("signup");
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: " + email);
    }
});

app.get('/login', (req, res) => {
    var html = `
    Log in
    <form action='/loggingin' method='post'>
    <div><input name='email' type='text' placeholder='email'></div>
    <div><input name='password' type='password' placeholder='password'></div>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/loginSubmit', (req, res) => {
    const missing = req.query.missing;
    res.render('loginSubmit', { missing: missing });
});

app.post('/signup', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (username == '' && email == '' && password == '') {
        console.log("all are empty");
        res.redirect('/signupSubmit?missing=1');
        return;
    } else if (username == '' && email == '') {
        console.log("name and email are empty");
        res.redirect('/signupSubmit?missing=2');
        return;
    } else if (username == '' && password == '') {
        console.log("name and password are empty");
        res.redirect('/signupSubmit?missing=3');
        return;
    } else if (email == '' && password == '') {
        console.log("email and password are empty");
        res.redirect('/signupSubmit?missing=4');
        return;
    } else if (username == '') {
        console.log("name is empty");
        res.redirect('/signupSubmit?missing=5');
        return;
    } else if (email == '') {
        console.log("email is empty");
        res.redirect('/signupSubmit?missing=6');
        return;
    } else if (password == '') {
        console.log("password is empty");
        res.redirect('/signupSubmit?missing=7');
        return;
    }

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().max(40).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, email, password });

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/signup");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(40).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/loginSubmit?missing=1");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/loggedIn');
        return;
    }
    else {
        console.log("incorrect password");
        res.redirect("/loginSubmit?missing=2");
        return;
    }
});

app.use('/loggedin', sessionValidation);
app.get('/loggedIn', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.redirect('/members');
});


app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/cat/:id', (req, res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: " + cat);
    }
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 