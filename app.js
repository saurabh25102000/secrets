//jshint esversion:6
require("dotenv").config()
const express = require("express")
const ejs = require("ejs")
const bodyParser = require("body-parser")
const mongoose = require("mongoose")
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")

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
  password: String
})

userSchema.plugin(passportLocalMongoose)

const User = new mongoose.model("User", userSchema)

passport.use(User.createStrategy())

passport.serializeUser(User.serializeUser())
passport.deserializeUser(User.deserializeUser())

app.get("/", (req, res)=>{
  res.render("home")
})

app.get("/login", (req, res)=>{
  res.render("login")
})

app.get("/register", (req, res)=>{
  res.render("register")
})

app.get("/secrets", (req, res)=>{
  // The below line was added so we can't display the "/secrets" page
  // after we logged out using the "back" button of the browser, which
  // would normally display the browser cache and thus expose the
  // "/secrets" page we want to protect. Code taken from this post.
  res.set(
        'Cache-Control',
        'no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0'
  );
  if(req.isAuthenticated()){
    res.render("secrets")
  }else{
    res.redirect("/login")
  }
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
