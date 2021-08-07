//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
//**const encrypt=require("mongoose-encryption");
//***const md5=require("md5");  HASHING
// const bcrypt=require("bcrypt"); //Hashing+Salting
// const saltrounds=10;
var GoogleStrategy = require('passport-google-oauth20').Strategy;
var findorCreate=require("mongoose-findorcreate");


//**userschema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});//Be aware of typos
//Note:We are encrypting just the password feild because we would need to verify users in our DB throug emails
//Though mongoose encryt, ecrypts and decrypts our password field accordingly
 //Collection (All steps were completed before making the collection)

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(session({
  secret:"Out little secret",
  resave:false,
  saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});
mongoose.set("useCreateIndex",true);
const userschema =new mongoose.Schema({   //proper mongoose schema than an ordinary Js object
  email: String,
  password: String,
  googleId:String,
  secret:String
});
userschema.plugin(passportLocalMongoose);
userschema.plugin(findorCreate);
const User = new mongoose.model("User", userschema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secret",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});
app.get("/auth/google",passport.authenticate("google",{scope:["profile"]})); //google authenticates the user

app.get("/auth/google/secret",passport.authenticate("google",{failureredirect:"/login"}),  //authenticated locally
function(req,res){
  res.redirect("/secrets");
});
app.get("/login", function(req, res) {
  res.render("login");
});
app.get("/register", function(req, res) {
  res.render("register");
});
app.get("/secrets",function(req,res){
  User.find({"secret":{$ne:null}},function(err,foundusers){
     if(err)
     {
       console.log(err);
     }
     else{
       if(foundusers)
       {
         res.render("secrets",{usersWithSecrets:foundusers});
       }
     }
  });
});
app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});
app.post("/submit",function(req,res){ //passport saves the users detatils in req
    const subsecret=req.body.secret;
    //console.log(req.user);
    User.findById(req.user.id,function(err,founduser) //from which userid did the request come
  {
    if(err){
      console.log(err);
    }
    else{
       if(founduser)
       {
         founduser.secret=subsecret;
         founduser.save(function(){
           res.redirect("/secrets");
         });
       }
    }
  });
});
app.get("/logout",function(req,res)
{
  req.logout();
  res.redirect("/");
});
app.post("/register", function(req, res) { //User is registering if he has entered for the first time
// bcrypt.hash(req.body.password,saltrounds,function(err,hash){
//   const newUser = new User({
//    email: req.body.username,
//     password:hash //converting the password into irreversible hash
//   });
//   newUser.save(function(err) {
//     if (!err) {
//       res.render("secrets");
//     } else {
//       console.log(err);
//     }
//   });
// });
User.register({username:req.body.username},req.body.password,function(err,user){
  if(err)
  {
    console.log(err);res.redirect("/register");
  }
  else{
    passport.authenticate("local")(req,res,function(){  //if the user is authenticated
      res.redirect("/secrets");
    });
  }
});

});
app.post("/login",function(req,res){  //If the user is logging we are verifying him
  // const username=req.body.username;
  // const password=req.body.password;  //do not forget to hash the password written while login
  // User.findOne({email:username},function(err,foundperson){
  //   if(err){
  //     console.log(err);
  //   }else{
  //     if(foundperson)
  //     {
  //       bcrypt.compare(password,foundperson.password,function(err,result){ //hashes the password and compares with registered hashed one
  //           if(result===true) //If matches
  //           {
  //             res.render("secrets");
  //           }
  //           else{
  //             //res.write("Incorrect password");
  //             res.redirect("/");
  //           }
  //       });
  //
  //
  //     }
  //     else{
  //       //res.write("Soorry!!,U are not registered");
  //       res.redirect("/register");
  //     }
  //   }
  // });
  const user=new User({
     username:req.body.username,
     password:req.body.password
    });
    req.login(user,function(err){   //passport method
      if(err)
      {
        console.log(err);
      }
      else{
        passport.authenticate("local")(req,res,function(){
          res.redirect("/secrets");
        });
      }
    });
});
app.listen(3000, function() {
  console.log("server stared");
});
