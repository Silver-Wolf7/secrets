//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require('passport-facebook').Strategy;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// initializing database
mongoose.connect("mongodb://localhost:27017/usersDB", {
    useNewUrlParser: true
});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// creating model after encryption
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});
passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secret",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


//creating routes 

app.get("/", function(req, res) {
    res.render("home");
});

app.get("/auth/google",	function(req, res){
    passport.authenticate("google", { scope: ["profile"] })(req, res);
});

app.get("/auth/google/secret", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

app.get("/auth/facebook",	function(req, res){
    passport.authenticate("facebook", { scope: ["public_profile"] })(req, res);
});

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.route("/login")
    .get(function(req, res) {
        res.render("login");
    })
    .post(function(req, res) {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });
        req.login(user, function(err) {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local")(req, res, function() {
                    res.redirect("/secrets");
                });
            }
        });
    });

app.route("/register")
    .get(function(req, res) {
        res.render("register");
    })
    .post(function(req, res) {
        User.register({username: req.body.username}, req.body.password, function(err, user) {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else {
                passport.authenticate("local")(req, res, function() {
                    res.redirect("/secrets");
                });
            }
        });
    });

app.route("/secrets")
    .get(function(req, res) {
        User.find({"secret": {$ne: null}}, function(err, foundUsers) {
            if (err) {
                console.log(err);
            } else {
                if (foundUsers) {
                    res.render("secrets", {usersWithSecrets: foundUsers});
                }
            }
        });
    });

app.route("/submit")
    .get(function(req, res) {
        if(req.isAuthenticated()) {
            res.render("submit");
        } else {
            res.redirect("/login");
        }
    })
    .post(function(req, res) {
        const submittedSecret = req.body.secret;
        User.findById(req.user.id, function(err, foundUser) {
            if(err) {
                console.log(err);
            } else {
                if(foundUser) {
                    foundUser.secret = submittedSecret;
                    foundUser.save(function() {
                        res.redirect("/secrets");
                    });
                }
            }
        });
    });

app.route("/logout")
    .get(function(req, res) {
        req.logout(function(err) {
            if (err) {
                console.log(err);
            } else {
                res.redirect("/");
            }
        });
    });

app.listen(3000, function(){
    console.log("Server started on port 3000");
});