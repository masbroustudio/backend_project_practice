const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session')
const routes = require('./router/friends.js')

let users = []

// Step 2 : You need to provide a manner in which it can be checked to see if the username 
// exists in the list of registered users, to avoid duplications and keep the username unique. 
// This is a utility function and not an endpoint.
const doesExist = (username)=>{
  let userswithsamename = users.filter((user)=>{
    return user.username === username
  });
  if(userswithsamename.length > 0){
    return true;
  } else {
    return false;
  }
}

// Step 3 : You will next check if the username and password match what you have in the list 
// of registered users. It returns a boolean depending on whether the credentials match or not. 
// This is also a utility function and not an endpoint.

const authenticatedUser = (username,password)=>{
  let validusers = users.filter((user)=>{
    return (user.username === username && user.password === password)
  });
  if(validusers.length > 0){
    return true;
  } else {
    return false;
  }
}

const app = express();

// Step 4 : You will now create and use a session object with user-defined secret, 
// as a middleware to intercept the requests and ensure that the session is valid 
// before processing the request.

app.use(session({secret:"fingerpint"},resave=true,saveUninitialized=true, maxAge=3600000));

app.use(express.json());

// Step 6 : You will now ensure that all operations restricted to auhtenticated users 
// are intercepted by the middleware. 
app.use("/friends", function auth(req,res,next){
   if(req.session.authorization) {
       token = req.session.authorization['accessToken'];
       jwt.verify(token, "access",(err,user)=>{
           if(!err){
               req.user = user;
               next();
           }
           else{
               return res.status(403).json({message: "User not authenticated"})
           }
        });
    } else {
        return res.status(403).json({message: "User not logged in"})
    }
});

// Step 5 : You will provide an endpoint for the registered users to login.
app.post("/login", (req,res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || !password) {
      return res.status(404).json({message: "Error logging in"});
  }

  if (authenticatedUser(username,password)) {
    let accessToken = jwt.sign({
      data: password
    }, 'access', { expiresIn: 60 * 60 });

    req.session.authorization = {
      accessToken,username
  }
  return res.status(200).send("User successfully logged in");
  } else {
    return res.status(208).json({message: "Invalid Login. Check username and password"});
  }
});

// Firstly, as the intent of this application is to provide access to the API endpoints only 
// to the authenticated users, you need to provide a way to register the users. 
// This endpoint will be a post request that accepts username and password through the body. 
// The user doesn’t have to be authenticated to access this endpoint.

app.post("/register", (req,res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (username && password) {
    if (!doesExist(username)) { 
      users.push({"username":username,"password":password});
      return res.status(200).json({message: "User successfully registred. Now you can login"});
    } else {
      return res.status(404).json({message: "User already exists!"});    
    }
  } 
  return res.status(404).json({message: "Unable to register user."});
});


const PORT =5000;

app.use("/friends", routes);

app.listen(PORT,()=>console.log("Server is running"));
