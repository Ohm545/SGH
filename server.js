import express, { query } from "express";
import path from "path";
import otpGenerator from "otp-generator";
import { fileURLToPath } from "url";
import nodemailer from "nodemailer";
import "dotenv/config";
import fs from 'fs';
import pkg from "pg";
import twilio from "twilio";
import cors from "cors";
import multer from 'multer';
const { Pool } = pkg;
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.set("view engine", "ejs");
// const upload = multer({dest:'uploads/'});
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
    res.sendFile(path.join(__dirname, "public", "lagunagepage.html"));
});

app.post("/official", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "officerlogin.html"));
});
app.post("/citizensignupG",(req,res)=>{
    res.sendFile(path.join(__dirname,"public",'citizensignupG.html'));
});
app.post("/signup1", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "signup.html"));
});
app.post("/citizenloginG",(req,res)=>{
    res.sendFile(path.join(__dirname,"public",'citizenloginG.html'));
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
app.post('/update-status', async (req, res) => {
    const { mobilenum, complaintdesc, status } = req.body;

    console.log("Received Data:", { mobilenum, complaintdesc, status });

    try {
        const checkComplaint = await pool.query(
            `SELECT * FROM complaint WHERE mobilenum = $1 AND complaint = $2`,
            [mobilenum, complaintdesc]
        );

        console.log("Database Query Result:", checkComplaint.rows);

        if (checkComplaint.rowCount === 0) {
            return res.status(404).json({ 
                message: "Complaint not found", 
                received: { mobilenum, complaintdesc } 
            });
        }

        const result = await pool.query(
            `UPDATE complaint SET status = $1 WHERE mobilenum = $2 AND complaint = $3 RETURNING *`,
            [status, mobilenum, complaintdesc]
        );
        await pool.query(`UPDATE status SET status=$1 WHERE mobilenumber=$2 AND complainttype=$3`,[status,mobilenum,complaintdesc]);
        res.json({ message: "Status updated successfully!", updatedComplaint: result.rows[0] });

    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});
app.post("/loginoff",async(req,res)=>{
    const otp = otpGenerator.generate(6,{text:true});
    const {mobile,password}=req.body;
    try {
        const response = await client.messages.create({
            body:`Verification ${otp}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to:mobile
        });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
        const result = await pool.query('SELECT post FROM verifyofficals WHERE phonenumber=$1', [mobile]);
        // console.log(result.rows[0].post); 
        if(result.rows[0].post=='Opreator')
        {
            res.sendFile(path.join(__dirname,"public","opreatordashboard.html"));
        }
        else
        {
            const departmentResult = await pool.query(`SELECT complaintdesc, complaintdep, taluka, mobilenum FROM "${result.rows[0].post}"`);
            res.render("department.ejs", { complaints: departmentResult.rows });

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
// const upload = multer({ dest: 'uploads/' }); 
const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            const uploadDir = "uploads/";
            if (!fs.existsSync(uploadDir)) {
                fs.mkdirSync(uploadDir, { recursive: true });
            }
            cb(null, uploadDir);
        },
        filename: (req, file, cb) => {
            const fileName = `${Date.now()}-${file.originalname}`;
            cb(null, fileName);
        }
    }),
    limits: {
        fileSize: 5 * 1024 * 1024,
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith("image/")) {
            cb(null, true);
        } else {
            cb(new Error("Only image files are allowed!"), false);
        }
    }
});
app.post('/your-backend-endpoint', upload.single('image'), async (req, res) => {
    try {
        const { mobile, complaintCategory, complaintType, problemDesc ,taluka,name,villageCity} = req.body;
        const imagePath = req.file ? req.file.path : null;

        console.log("Mobile:", mobile);
        console.log("Complaint Category:", complaintCategory);
        console.log("Complaint Type:", complaintType);
        console.log("Problem Description:", problemDesc);
        console.log("Uploaded Image Path:", imagePath);

        const result = await pool.query(
            `UPDATE citizenverify 
             SET complaintdesc = $1, complaintcategory = $2, complainttype = $3, imagepath = $4 
             WHERE phonenumber = $5`,
            [problemDesc, complaintCategory, complaintType, imagePath, mobile]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: "No citizen found with this phone number" });
        }
        await pool.query('INSERT INTO complaint (complaint, department, taluka, mobilenum, nameofcitizen, village, complaintdesc, image_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',[complaintType,complaintCategory,taluka,mobile,name,villageCity,problemDesc,imagePath])
        res.json({ success: true, message: "Complaint updated successfully", imagePath });
        const status = 'Logged';
        await pool.query('INSERT INTO status (complaint,status,mobilenumber,taluka) VALUES ($1,$2,$3,$4)',[problemDesc,status,mobile,taluka]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
app.post("/omlogin", async (req, res) => {
    const { mobile , pass } = req.body;

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
app.get("/complaintcard",async(req,res)=>{
    const complaints = await pool.query('SELECT complaint,department,taluka,mobilenum,complaintdesc FROM complaint')
    res.json(complaints.rows);
});
app.use(express.static("public")); 

app.post("/redirect",(req,res)=>{
    // res.sendFile(path.join(__dirname,"public","deapartment.html"));
    res.status(200).json({ message: "Redirect successful" });
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
app.use(express.json()); 
app.post("/res", async (req, res) => {
    const { options, complaintInfo } = req.body;
    const optionsString = options.join(',');
    if (!Array.isArray(options) || options.length === 0) {
      return res.status(400).json({ error: "Invalid or missing 'options' array." });
    }
    if (!complaintInfo || typeof complaintInfo !== 'object') {
      return res.status(400).json({ error: "Invalid or missing 'complaintInfo' object." });
    }
  
    try {
      for (const option of options) {
        const tableName = option.replace(/\s+/g, '_').toLowerCase();
        const createTableSQL = `
          CREATE TABLE IF NOT EXISTS "${tableName}" (
            id SERIAL PRIMARY KEY,
            complaintdesc VARCHAR(250),
            complaintdep VARCHAR(250),
            problemdesc VARCHAR(500),
            taluka VARCHAR(250),
            mobilenum VARCHAR(15)
          )
        `;
        await pool.query(createTableSQL);
        const insertDataSQL = `
          INSERT INTO "${tableName}" (complaintdesc, complaintdep, taluka, mobilenum,problemdesc)
          VALUES ($1, $2, $3, $4,$5)
        `;
        await pool.query(`INSERT INTO ${complaintInfo.talukaS} (complaintdep,complaintdesc,mobilenum,taluka,complaintcategory) VALUES ($1,$2,$3,$4,$5)`,[optionsString,complaintInfo.problemS,complaintInfo.mobilenumS,complaintInfo.talukaS,complaintInfo.complaintS]);
        await pool.query(insertDataSQL, [
          complaintInfo.complaintS,
          optionsString,
          complaintInfo.talukaS,
          complaintInfo.mobilenumS,
          complaintInfo.problemS
        ]);
      }
  
      res.json({ message: "Tables created and data inserted successfully." });
    } catch (error) {
      console.error("Error:", error);
      res.status(500).json({ error: "An error occurred while processing your request." });
    }
    // const status = 'Assigned'
    // await pool.query('UPDATE status SET status = $1 WHERE mobilenumber = $2',[status,mobilenum]);
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
