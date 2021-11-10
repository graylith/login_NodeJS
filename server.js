const express = require("express");
const app = express();
const path = require("path");
const bodyParser = require("body-parser")
const User = require('./model/user')
const bcrypt = require("bcryptjs")
const jwt = require('jsonwebtoken');
const mongoose = require("mongoose")

const JWT_SECRET = "aasasasasohfsdklgsdlfas;ofjsdgbjkgbfljsdopfhsdgjk"

mongoose.connect('mongodb://localhost:27017/login-app-db', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
app.use("/",express.static(path.join(__dirname,'static')));

app.use(bodyParser.json())

app.post("/api/register", async (req, res)=>{
    console.log(req.body)

    const {username, password: plainTextPassword} = req.body;

    if(!username || typeof username !== "string"){
        return res.json({status: 'error', error: "Invalid Username"})
    }

    if(!plainTextPassword || typeof plainTextPassword !== "string"){
        return res.json({status: 'error', error: "Invalid password"})
    }

    if(plainTextPassword.length < 5){
        return res.json({status: 'error', error:"Short length password, min length should be 5"})
    }

    const password = await bcrypt.hash(plainTextPassword, 10)
    try{
        const response = await User.create({
            username, 
            password
        })
        console.log("User created succesfully", response)
    }catch (error){
        console.log(JSON.stringify(error))
        if(error.code === 11000){
            return res.json({status: 'error', error: "Username already in use"})
        }
        throw error
        
    }
    return res.json({status: 'ok'})
})

app.post('/api/login', async (req, res)=>{
    const {username, password} = req.body;
    const user = await User.findOne({username}).lean()

    if(!user){
        return res.json({status: "error", error:"Invalid Username/password"})
    }
    if(await bcrypt.compare(password, user.password)){
        const token = jwt.sign({
            id: user._id, 
            username: user.username
        }, JWT_SECRET)

        return res.json({status: "ok", data: token})
    }
    res.json({status: "error", error: "Invalid Username/password"})
})

app.post("/api/reset-password", async (req, res)=>{
    const {newpassword, token} = req.body;
    try{
    const user = jwt.verify(token, JWT_SECRET)
    const _id = user.id;
    const hashedpassword = await bcrypt.hash(newpassword, 10)
    await User.updateOne({_id},
    {
        $set: {password : hashedpassword}
    }    
    )

    console.log(user)
    res.json({status: "ok"})
    }catch(error){
        return res.json({status:"error", error:"someone is trying to mess up"})
    }
})

app.listen(9999, ()=>{
    console.log("server running at 9999")
})