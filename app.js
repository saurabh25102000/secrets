//jshint esversion:6
require("dotenv").config()
const express = require("express")
const ejs = require("ejs")
const bodyParser = require("body-parser")
const mongoose = require("mongoose")
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy
const findOrCreate = require('mongoose-findorcreate')

const app = express()

app.use(express.static("public"))
app.set("view engine", "ejs")
app.use(bodyParser.urlencoded({
  extended: true
}))

app.use(session({
  secret: "My little secret",
  resave: false,
  saveUninitialized: true
}))

app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true})

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secrets: [String]
})

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

const User = new mongoose.model("User", userSchema)

passport.use(User.createStrategy())

//these below serialization and deserialization was for local Strategy only from passport-local-mongoose documentation
// passport.serializeUser(User.serializeUser())
// passport.deserializeUser(User.deserializeUser())

//so we have update serialization and deserialization which will work for any type of Strategy from passport documentation
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res)=>{
  res.render("home")
})

app.get("/login", (req, res)=>{
  res.render("login")
})

app.get("/register", (req, res)=>{
  res.render("register")
})

app.get("/auth/google", passport.authenticate("google", {scope: ["profile"] }))
app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // successfull authentication, redirect secrets
    res.redirect("/secrets")
  })
app.get("/secrets", (req, res)=>{
  // The below line was added so we can't display the "/secrets" page
  // after we logged out using the "back" button of the browser, which
  // would normally display the browser cache and thus expose the
  // "/secrets" page we want to protect. Code taken from this post.

  // later added: after level 6: google OAuth20
  //this below code is no longer needed, bcz secret page is not privilaged which require authentication
  // so we will remove authentication, so that any user (login or not) can see other's secrets posted by anonymous

  // res.set(
  //       'Cache-Control',
  //       'no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0'
  // );
  // if(req.isAuthenticated()){
  //   res.render("secrets")
  // }else{
  //   res.redirect("/login")
  // }

  // get all user's secrets with their profile
  User.find({"secrets": {$ne: null}}, function (err, foundUsers) {
    if(err){
      console.log(err)
    }else{
      if(foundUsers){
        let authenticated = false
        if(req.isAuthenticated()){
          authenticated = true
        }
        res.render("secrets", {usersWithSecrets: foundUsers, authenticated: authenticated})
      }
    }
  })
})

app.get("/logout", (req, res)=>{
  req.logout((err)=>{
    if(err){
      console.log(err)
    }else{
      res.redirect("/")
    }
  })
})

app.get("/submit", (req, res)=>{
  if(req.isAuthenticated()){
    res.render("submit")
  }else{
    res.redirect("/login")
  }
})

app.post("/submit", (req, res)=>{
  const submittedSecret = req.body.secret
  User.findById(req.user.id, function (err, foundUser) {
    if(err){
      console.log(err)
    }else{
      if(foundUser){
        foundUser.secrets.push(submittedSecret)
        foundUser.save(function () {
          res.redirect("/secrets")
        })
      }
    }
  })
})

app.post("/register", (req, res)=>{

  User.register({username: req.body.username}, req.body.password, function (err, user) {
    if(err){
      console.log(err)
      res.redirect("/register")
    }else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets")
      })
    }
  })

})

// this is the new login route, which authenticates first and THEN
// does the login (which is required to create the session, or so I
// understood from the passport.js documentation).
// A failed login (wrong password) will give the browser error
// "unauthorized".

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}))

// this is the original login route (with the bug):
// app.post("/login", (req, res)=>{
//
//   const user = new User({
//     username: req.body.username,
//     password: req.body.password
//   })
//
//   req.login(user, function(err){
//     if(err){
//       console.log(err)
//     }else{
//       passport.authenticate("local")(req, res, function () {
//         res.redirect("/secrets")
//       })
//     }
//   })
//
// })

app.listen(3000, ()=>{
  console.log("app is listening on port 3000")
})
