import express from "express";
import path from "path";
import otpGenerator from "otp-generator";
import { fileURLToPath } from "url";
import nodemailer from "nodemailer";
import "dotenv/config";
import pkg from "pg";
import twilio from "twilio";

const { Pool } = pkg;
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "homepage.html"));
});

app.post("/official", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/signup1", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "signup.html"));
});

app.post("/login1", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

var Email = "";
var citizenEmail="";
app.post("/get-otp", async (req, res) => {
    const { officialname, email, phonenumber, pincode, post, password } = req.body;

    if (!officialname || !email || !phonenumber || !pincode || !post || !password) {
        console.log("Missing required fields");
        return res.status(400).json({ error: "All fields are required" });
    }

    try {
        await pool.query(
            'INSERT INTO verifyofficals (officialname, email, phonenumber, pincode, post, passwordoff) VALUES ($1, $2, $3, $4, $5, $6)',
            [officialname, email, phonenumber, pincode, post, password]
        );

        Email = email;
        console.log(`User ${email} registered successfully`);

        const otp = otpGenerator.generate(6, { digits: true });
        console.log(`Generated OTP for ${email}: ${otp}`);

        try {
            const transporter = nodemailer.createTransport({
                service: "gmail",
                auth: {
                    user: "ohmpatel655@gmail.com",
                    pass: process.env.GG_PASS, 
                },
            });

            const mailOptions = {
                from: "ohmpatel655@gmail.com",
                to: email,
                subject: "Verification",
                text: `Your OTP is: ${otp}`,
            };

            await transporter.sendMail(mailOptions);
            console.log(`OTP sent to ${email}`);
        } catch (error) {
            console.error("Error sending OTP:", error);
            return res.status(500).json({ error: "Error sending OTP." });
        }

        const expiryTime = new Date(Date.now() + 5 * 60 * 1000);
        await pool.query('UPDATE verifyofficals SET otp = $1, expiryTime = $2 WHERE email = $3', [otp, expiryTime, email]);
        console.log(`OTP stored in DB for ${email}, expires at ${expiryTime}`);
        res.sendFile(path.join(__dirname, "public", "otp.html"));

    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ error: "Database error" });
    }
});
const accountSid = process.env.TWILIO_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = new twilio(accountSid, authToken);

app.post("/loginoff",async(req,res)=>{
    const otp = otpGenerator.generate(6,{text:true});
    const {mobile,password}=req.body;
    try {
        const response = await client.messages.create({
            body:`Verification ${otp}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to:mobile
        });
        // res.status(200).json({ success: true, message: "SMS sent!", sid: response.sid });
        res.sendFile(path.join(__dirname,"public","opreatordashboard.html"));
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
});
app.post("/citizen",(req,res)=>{
    res.sendFile(path.join(__dirname,"public","citizenlogin.html"));
});
app.post("/citizensignup",(req,res)=>{
    res.sendFile(path.join(__dirname,"public","citizen.html"));
});
app.post("/citizenlogin",(req,res)=>{
    res.sendFile(path.join(__dirname,"public","citizenlogin.html"));
});
app.post("/omlogin", async (req, res) => {
    const { mobile, pass } = req.body;

    try {
        const { rows } = await pool.query('SELECT phonenumber FROM citizenverify WHERE passwordofcitizen = $1', [pass]);

        if (rows.length === 0) {
            return res.status(400).json({ error: "Invalid password" });
        }

        const { phonenumber } = rows[0];

        if (mobile !== phonenumber) {
            return res.status(400).json({ error: "Invalid mobile number" });
        }

        res.sendFile(path.join(__dirname, "public", "citizendashboard.html"));
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.post("/signup",async(req,res)=>{
    const  otp1= otpGenerator.generate(6,{text:true});
    const {name,phonenumber,email,taluka,district,place,password}=req.body;
    const expiryTime=new Date(Date.now()+5*60*1000);
    citizenEmail=email;
    await pool.query('INSERT IGNORE INTO citizenverify (nameofcitizen,phonenumber,email,taluka,district,place,passwordofcitizen,otp,expirytime) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',[name,phonenumber,email,taluka,district,place,password,otp1,expiryTime]);
    try{
        const transporter = nodemailer.createTransport({
            service:'gmail',
            auth: {
                user: "ohmpatel655@gmail.com",
                pass: process.env.GG_PASS, 
            },
        })
        const mailOptions = {
            from:'ohmpatel655@gmail.com',
            to:email,
            subject:'Verification',
            text:`Your OTP is ${otp1}`
        }
        await transporter.sendMail(mailOptions);
        res.sendFile(path.join(__dirname,"public","otp.html"));
    }
    catch(error){
        console.error("Error sending OTP:", error);
        return res.status(500).json({ error: "Error sending OTP." });
    }
});
app.get("/complaintcard",(req,res)=>{
    const complaints =[
        { id: 1, title: "Card 1", description: "This is card 1" },
        { id: 2, title: "Card 2", description: "This is card 2" },
        { id: 3, title: "Card 3", description: "This is card 3" }
    ]
    res.json(complaints);
});
app.post("/redirect",(req,res)=>{
    res.sendFile(path.join(__dirname,"public","department.html"));
});
app.post("/citizenverify",async(req,res)=>{
    const {otptemp}=req.body;
    const {otp,expiryTime}=await pool.query('SELECT otp,expirytime FROM citizenverify WHERE email=$1',[citizenEmail]);
    const currentTime=Date.now();
    try{
    if(String(otptemp).trim() !== String(otp).trim())
    {
        console.log('Invalid OTP');
        return res.sendStatus(400).json({error:"Invalid Email"});
        await pool.query('DELETE FROM citizenverify WHERE email = $1', [Email]);
    }
    else if(currentTime>expiryTime)
    {
        console.log('Time limit expired');
        return res.sendStatus(400).json({error:"Time limit expired"});
        await pool.query('DELETE FROM citizenverify WHERE email = $1', [Email]);
    }
    return res.json({message:'Done'});
}
catch(error)
{
    return res.sendStatus(400).json({error:"Internal server error"});
}
});
app.post("/verify", async (req, res) => {
    try {
        const currentTime = Date.now();
        console.log(`Verifying OTP for ${Email} at ${new Date(currentTime)}`);
        const result = await pool.query('SELECT otp, expiryTime FROM verifyofficals WHERE email = $1',[Email]);

        if (result.rows.length === 0) {
            console.log(`No OTP found for ${Email}`);
            return res.status(400).json({ error: "Invalid email" });
        }

        const { otp , expiryTime } = result.rows[0];
        const { OTP } = req.body;
        if(OTP=="NULL" && currentTime > expiryTime)
        {
            await pool.query('DELETE FROM verifyofficals WHERE email = $1', [Email]);
            return res.status(400).json({error:"verify it"});
        }

        if (String(otp).trim() !== String(OTP).trim()) {
            console.log(`Incorrect OTP for ${Email}. Deleting record.`);
            await pool.query('DELETE FROM verifyofficals WHERE email = $1', [Email]);
            return res.status(400).json({ error: "Invalid OTP" });
        }

        if (currentTime > new Date(expiryTime)) {
            console.log(`OTP expired for ${Email}. Deleting record.`);
            await pool.query('DELETE FROM verifyofficals WHERE email = $1', [Email]);
            return res.status(400).json({ error: "OTP expired" });
        }

        console.log(`OTP verification successful for ${Email}`);
        res.json({ message: "OTP verified successfully!" });

    } catch (error) {
        console.error("Error verifying OTP:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.listen(5000, () => {
    console.log("Server running on http://localhost:5000");
});
