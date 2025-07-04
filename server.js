import express, { query } from "express";
import path from "path";
import otpGenerator from "otp-generator";
import { fileURLToPath } from "url";
import nodemailer from "nodemailer";
import session from "express-session";
import 'dotenv/config';
import fs from 'fs';
import pkg from "pg";
import twilio from "twilio";
import cors from "cors";
import multer from 'multer';
import axios from 'axios';
import FormData from "form-data";
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import { v2 as cloudinary } from 'cloudinary';
import { Readable } from "stream";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
// import { console } from "inspector";
const { Pool } = pkg;
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.set("view engine", "ejs");
console.log("DATABASE_URL:", process.env.DATABASE_URL);

// const upload = multer({dest:'uploads/'});
const pool = new Pool({
        user: process.env.DB_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_NAME,
        password: process.env.DB_PASS,
        port: process.env.DB_PORT,
        // connectionString: process.env.DATABASE_URL,
        // ssl: { rejectUnauthorized: false }
});
app.use(session({
    secret: process.env.OHMG,
    resave: false,
    saveUninitialized: true
}));
// dotenv.config();

// const pool = new pg.Pool({
//     connectionString: process.env.DATABASE_URL, // Use Neon connection string
//     ssl: { rejectUnauthorized: false }, // Required for Neon DB
//   });
console.log("DB_USER:", process.env.DB_USER);  
console.log("DB_PASS:", process.env.DB_PASS);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, "public")));
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
const accountSid = process.env.OHMB;
const authToken = process.env.OHMA;
const client = new twilio(accountSid, authToken);
app.post('/update-status', async (req, res) => {
    const { mobilenum, complaintdesc, status, department , complaintid } = req.body;
    console.log(mobilenum);
    console.log("Received Data:", { mobilenum, complaintdesc, status, department });

    const department1 = department.toLowerCase().replace(/\s+/g, '_'); // Format table name
    console.log("Formatted Department Table Name:", department1);

    const client = await pool.connect(); // Start transaction

    try {
        await client.query("BEGIN"); // Start transaction

        // Check if complaint exists
        const checkComplaint = await client.query(
            `SELECT * FROM complaint WHERE complaintid = $1`,
            [complaintid]
        );

        console.log("Database Query Result:", checkComplaint.rows);

        if (checkComplaint.rowCount === 0) {
            await client.query("ROLLBACK"); // Rollback transaction
            return res.status(404).json({ 
                message: "Complaint not found", 
                received: { mobilenum, complaintdesc } 
            });
        }

        // Update department table
        const updateDept = await client.query(
            `UPDATE ${department1} SET status = $1 WHERE complaintid = $2 RETURNING *`,
            [status, complaintid]
        );

        if (updateDept.rowCount === 0) {
            throw new Error(`No matching record in ${department1} table!`);
        }

        // Update main complaint table
        const updateComplaint = await client.query(
            `UPDATE complaint SET ostatus = $1 WHERE complaintid = $2 RETURNING *`,
            [status,complaintid]
        );

        // Update taluka table
        const updateTaluka = await client.query(
            `UPDATE ${checkComplaint.rows[0].taluka} SET status = $1 WHERE complaintid = $2 RETURNING *`,
            [status, complaintid]
        );

        // Update global status table
        const updateStatus = await client.query(
            `UPDATE status SET status=$1 WHERE complaintid = $2 RETURNING *`,
            [status, complaintid]
        );

        await client.query("COMMIT"); // Commit transaction

        res.json({ 
            message: "Status updated successfully!", 
            updatedComplaint: updateComplaint.rows[0],
            departmentUpdate: updateDept.rows[0],
            talukaUpdate: updateTaluka.rows[0],
            statusUpdate: updateStatus.rows[0]
        });

    } catch (error) {
        await client.query("ROLLBACK"); // Rollback transaction on error
        console.error("Database error:", error);
        res.status(500).json({ message: "Internal Server Error", error: error.message });
    } finally {
        client.release(); // Release client
    }
});

app.get("/omcitizen", async (req, res) => {
    try {
        let mobile = req.query.mobile.trim(); // Remove spaces

        // Ensure mobile number has "+"
        if (!mobile.startsWith("+")) {
            mobile = `+${mobile}`;
        }

        console.log("Formatted mobile number:", mobile);

        const result = await pool.query(
            "SELECT * FROM complaint WHERE mobilenum = $1",
            [ mobile]
        );

        // console.log("Query result:", result.rows);

        res.json(result.rows);
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: "Database query failed" });
    }
});



app.get("/plot-graphs", async (req, res) => {
    try {
      const result = await pool.query('SELECT status FROM ahwa');
      let pending = 0;
      let resolved = 0;
      result.rows.forEach(row => {
        if (row.status === "Resolved") {
            resolved++;
        } else {
            pending++;
        }
    });

    res.json({ resolved, pending });
    } catch (error) {
      console.error("Error fetching data:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  });
var postom = "";
app.post("/loginoff",async(req,res)=>{
    // const otp = otpGenerator.generate(6,{text:true});
    const {mobile,password}=req.body;
    // try {
    //     const response = await client.messages.create({
    //         body:`Verification ${otp}`,
    //         from: process.env.OHM_NUMBER,
    //         to:mobile
    //     });
    //     } catch (error) {
    //         res.status(500).json({ success: false, error: error.message });
    //     }
        const result = await pool.query('SELECT post FROM verifyofficals WHERE phonenumber=$1', [mobile]);
        // console.log(result.rows[0].post); 
        if(result.rows[0].post=='Opreator')
        {
            res.sendFile(path.join(__dirname,"public","opreatordashboard.html"));
        }
        else if(result.rows[0].post=='mamlatdar-ahwa')
        {
            req.session.mamlatdar={
                post:"mamlatdar-ahwa"
            }
            res.sendFile(path.join(__dirname,"public","mamlatdar.html"));
        }
        else if(result.rows[0].post=='mamlatdar-subir')
        {
            req.session.mamlatdar={
                post:"mamlatdar-subir"
            }
            res.sendFile(path.join(__dirname,"public","mamlatdar.html")); 
        }
        else if(result.rows[0].post=='mamlatdar-waghai')
        {
            req.session.mamlatdar={
                post:"mamlatdar-waghai"
            }
            res.sendFile(path.join(__dirname,"public","mamlatdar.html"));      
        }
        else if(result.rows[0].post=="Collector")
        {
            res.sendFile(path.join(__dirname,"public","admin.html"));
        }
        else if(result.rows[0].post=='SDM')
        {
            res.sendFile(path.join(__dirname,"public","sdm.html"));
        }
        else if(result.rows[0].post=='Collector')
        {
            res.sendFile(path.join(__dirname,"public","admin.html"));
        }
        else if(result.rows[0].post=='grampanchayat')
        {
            const result = await pool.query('SELECT village FROM verifyofficals WHERE phonenumber = $1',[mobile]);
            const village = result.rows[0].village;
            req.session.grampanchayat={
                post:village
            }
            res.sendFile(path.join(__dirname,"public","grampanchayat.html"));
        }
        else if(result.rows[0].post=='Talati')
        {
            // await pool.query()
            req.session.talati={
                // village:"";
            }
        }
        else
        {
            // const departmentResult = await pool.query(`SELECT complaintdesc, complaintdep, taluka, mobilenum FROM "${result.rows[0].post}"`);
            // // res.render("department.ejs", { complaint: departmentResult.rows });
            // // res.sendFile(path.join(__dirname,"public","de.html"));
            postom = result.rows[0].post;
            res.sendFile(path.join(__dirname, "public", "de.html"));

        }
});
app.get('/api/complaints', async (req, res) => {
    try {
        const department = postom;  // Ensure `postom` is correctly assigned
        console.log('Department:', department);

        const departmentResult = await pool.query(
            `SELECT problemdesc, complaintdep, taluka, mobilenum, status, complaintid, village, image_url, image_url_proof, proloc, sdate, fdate 
            FROM "${department}" WHERE status = $1`, 
            ['Assigned']
        );

        if (departmentResult.rows.length === 0) {
            return res.json({ complaints: [], department: department });  // Always send department name
        }

        res.json({ complaints: departmentResult.rows, department: department });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});


  app.get('/api/complaints/admin/:status', async (req, res) => {
    try {
        const { status } = req.params;
        const result = await pool.query(
            "SELECT * FROM complaint WHERE ostatus = $1",
            [status]
        );

        res.json({ complaints: result.rows });
    } catch (error) {
        console.error("Error fetching SDM complaints:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
app.get('/api/complaints/gmp/:status', async (req, res) => {
    try {
        const { status } = req.params;
        const village = req.session.grampanchayat?.post; 
        
        if (!village) {
            return res.status(400).json({ error: "Grampanchayat data not found in session" });
        }

        console.log("Village Name:", village);

        const result = await pool.query(
            "SELECT * FROM complaint WHERE village = $1 AND ostatus = $2",
            [village,status]
        );
        console.log("Fetched Complaints:", result.rows);
        res.json({ complaints: result.rows });
    } catch (error) {
        console.error("Error fetching Grampanchayat complaints:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
app.get('/api/complaints/sdm/:status', async (req, res) => {
    try {
        const { status } = req.params;
        let status1 = '';
        if(status==='Redirected')
        {
            status1 = 'Assigned';
        }
        else if(status==='On Hold')
        {
            status1 = 'On Hold';
        }
        else
        {
            status1 = status;
        }
        const result = await pool.query(
            "SELECT * FROM complaint WHERE ostatus = $1",
            [status1]
        );

        res.json({ complaints: result.rows });
    } catch (error) {
        console.error("Error fetching SDM complaints:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
  app.get('/api/complaints/taluka/:status', async (req, res) => {
    try {
        if (!req.session.mamlatdar || !req.session.mamlatdar.post) {
            return res.status(401).json({ error: "Unauthorized: Mamlatdar not logged in" });
        }

        const { status } = req.params;
        let tableName = "";
        if (req.session.mamlatdar.post === "mamlatdar-ahwa") {
            tableName = "ahwa";
        } else if (req.session.mamlatdar.post === "mamlatdar-subir") {
            tableName = "subir";
        } else if (req.session.mamlatdar.post === "mamlatdar-waghai") {
            tableName = "waghai";
        }
        else {
            return res.status(400).json({ error: "Invalid Mamlatdar post" });
        }
        var status12 = status;
        if(status === 'Redirected')
        {
            status12 = 'Assigned';
        }
        else
        {
            status12 = status;
        }
        const result = await pool.query(`SELECT * FROM ${tableName} WHERE status = $1`, [status12]);

        res.json({ complaints: result.rows });
    } catch (error) {
        console.error("Error fetching complaints:", error);
        res.status(500).json({ error: "Internal Server Error" });
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
// const upload = multer({ dest: 'uploads/' });app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Configure Multer for file uploads
// Cloudinary Configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});
const storage3 = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        const isAudio = file.mimetype.startsWith("audio");
        return {
            folder: 'grievance_express',
            resource_type: isAudio ? "video" : "image", 
            public_id: `${req.body.mobile || 'unknown'}-${Date.now()}`
        };
    }
});
const upload1 = multer({ storage: storage3 });
app.post("/uploadsom", upload1.fields([
    { name: 'image', maxCount: 1 }, 
    { name: 'audio', maxCount: 1 }  
]), async (req, res) => {
    try {
        const { mobile, complaintCategory, complaintType, problemDesc, taluka, name, villageCity ,exactLocation} = req.body;
        const imagePath = req.files['image'] ? req.files['image'][0].path : null;
        const audioPath = req.files['audio'] ? req.files['audio'][0].path : null;
        const complaintid = `${mobile}-${Date.now()}`;

        console.log("✔ Received Complaint Data:", { 
            mobile, complaintCategory, complaintType, problemDesc, taluka, name, villageCity, imagePath, audioPath 
        });

        if (!mobile || !complaintCategory || !complaintType || !problemDesc || !taluka || !name || !villageCity) {
            return res.status(400).json({ error: "All fields are required" });
        }
        const transcript = await transcribeWithElevenLabs(audioPath);
        const om = await processGujaratiText(transcript);
        console.log(om);
        console.log(transcript);
        // ✅ Update Citizen Record
        const updateResult = await pool.query(
            `UPDATE citizenverify 
             SET complaintdesc = $1, complaintcategory = $2, complainttype = $3, 
                 imagepath = COALESCE($4, imagepath)
             WHERE phonenumber = $5 
             RETURNING *`,
            [om, complaintCategory, complaintType, imagePath, mobile]
        );

        if (updateResult.rowCount === 0) {
            return res.status(404).json({ error: "No citizen found with this phone number" });
        }
        const today = new Date().toISOString().split('T')[0];
        console.log(today);

        // ✅ Insert into Complaint Table
        await pool.query(
            `INSERT INTO complaint (complaint, department, taluka, mobilenum, nameofcitizen, village, complaintdesc, image_url, ostatus, complaintid,proloc,sdate) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, NULL), COALESCE($9, NULL), $10,$11,$12)`,
            [complaintType, complaintCategory, taluka, mobile, name, villageCity, om , imagePath, 'Logged', complaintid,exactLocation,today]
        );

        // ✅ Insert into Status Table
        const status = "Logged";
        await pool.query(
            `INSERT INTO status (complaint, status, mobilenumber, taluka, complainttype, complaintcategory,complaintid,image_url,village,sdate) 
             VALUES ($1, $2, $3, $4, $5, $6,$7,$8,$9,$10)`,
            [om, status, mobile, taluka, complaintType, complaintCategory,complaintid,imagePath,villageCity,today]
        );

        // ✅ Insert into Taluka Table
        await pool.query(
            `INSERT INTO ${taluka} (complaintdep, complaintdesc, mobilenum, complaintcategory, status, image_url,complaintid,village,sdate) 
             VALUES ($1, $2, $3, $4, $5, COALESCE($6, NULL),$7,$8,$9)`,
            [complaintCategory, om, mobile, complaintType, 'Logged', imagePath,complaintid,villageCity,today]
        );

        res.json({ 
            success: true, 
            message: "Complaint submitted successfully", 
            imagePath,
            audioPath,
            data: { mobile, complaintCategory, complaintType, taluka, name, villageCity, problemDesc }
        });

    } catch (err) {
        console.error("❌ Error Handling Complaint:", err);
        res.status(500).json({ error: "Internal Server Error", details: err.message });
    }
});


// ✅ Error handling middleware
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: `Upload error: ${err.message}` });
    }
    console.error(err.stack);
    res.status(500).json({ error: err.message || 'Something went wrong!' });
});
app.post("/omloginG", async (req, res) => {
    const { mobile, pass } = req.body; 

    // Validate input
    if (!mobile || !pass) {
        return res.status(400).json({ error: "Mobile and password are required" });
    }

    try {
        // Query database to get user info based on mobile number
        const { rows } = await pool.query(
            "SELECT passwordofcitizen, phonenumber FROM citizenverify WHERE phonenumber = $1",
            [mobile]
        );

        if (rows.length === 0) {
            return res.status(400).json({ error: "Invalid Mobile Number" });
        }

        // Retrieve the hashed password from the database
        const storedHashedPassword = rows[0].passwordofcitizen; 

        // Verify the hashed password exists
        if (!storedHashedPassword) {
            return res.status(500).json({ error: "User record is missing password" });
        }

        // Use bcrypt to compare the entered password with the stored hashed password
        const isMatch = await bcrypt.compare(pass, storedHashedPassword);

        if (pass != storedHashedPassword) {
            return res.status(400).json({ error: "Invalid Password" });
        }

        // // Prepare the payload with mobile number
        // const payload = { mobile: rows[0].phonenumber }; 

        // // Generate JWT token with a 24-hour expiry
        // const token = jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: '24h' });

        // // Send the JWT token in the response
        // res.json({ token });
        res.sendFile(path.join(__dirname,"public","citizendashboardG.html"));
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.post("/omlogin", async (req, res) => {
    const { mobile, pass } = req.body; 

    // Validate input
    if (!mobile || !pass) {
        return res.status(400).json({ error: "Mobile and password are required" });
    }

    try {
        // Query database to get user info based on mobile number
        const { rows } = await pool.query(
            "SELECT passwordofcitizen, phonenumber FROM citizenverify WHERE phonenumber = $1",
            [mobile]
        );

        if (rows.length === 0) {
            return res.status(400).json({ error: "Invalid Mobile Number" });
        }

        // Retrieve the hashed password from the database
        const storedHashedPassword = rows[0].passwordofcitizen; 

        // Verify the hashed password exists
        if (!storedHashedPassword) {
            return res.status(500).json({ error: "User record is missing password" });
        }

        // Use bcrypt to compare the entered password with the stored hashed password
        const isMatch = await bcrypt.compare(pass, storedHashedPassword);

        if (pass != storedHashedPassword) {
            return res.status(400).json({ error: "Invalid Password" });
        }

        // // Prepare the payload with mobile number
        // const payload = { mobile: rows[0].phonenumber }; 

        // // Generate JWT token with a 24-hour expiry
        // const token = jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: '24h' });

        // // Send the JWT token in the response
        // res.json({ token });
        res.sendFile(path.join(__dirname,"public","citizendashboard.html"));
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

const storage5 = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        return {
            folder: 'grievance_express',
            resource_type: "image", 
            public_id: `${req.body.mobile || 'unknown'}-${Date.now()}`
        };
    }
});
app.use(express.json()); // Middleware to parse JSON
app.get("/getProfile", async (req, res) => {
    try {
        const { mobile } = req.query;

        if (!mobile) {
            return res.status(400).json({ error: "Mobile number is required" });
        }

        // Query to get citizen profile
        const result = await pool.query(
            "SELECT nameofcitizen, phonenumber, email, taluka, village FROM citizenverify WHERE phonenumber = $1",
            [mobile]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Profile not found" });
        }

        res.json(result.rows[0]);

    } catch (error) {
        console.error("Database Error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/feedback", async(req, res) => {
  const { complaintID, satisfaction, additionalFeedback } = req.body;
  
  let stringom = `${satisfaction}, ${additionalFeedback || "No additional feedback"}`;
  console.log("Received Feedback:");
  console.log("Complaint ID:", complaintID);
  console.log("Satisfaction:", satisfaction);
  console.log("Additional Feedback:", additionalFeedback);
  console.log("Om:",stringom);
    await pool.query('UPDATE complaint SET feedback = $1 WHERE complaintid=$2',[stringom,complaintID]);
    await pool.query('UPDATE status SET feedback = $1 WHERE complaintid=$2',[stringom,complaintID]);
  res.json({ message: "Feedback received successfully!" });
});

app.get("/api/get-official/:id", async (req, res) => {
    try {
        const { id } = req.params;

        let query = "";
        let queryParam = [];

        // Check if ID matches Mamlatdar or SDM
        if (id === 'MAMLATDAR-AHWA') {
            query = 'SELECT officialname, phonenumber, email FROM verifyofficals WHERE post = $1';
            queryParam = ['mamlatdar-ahwa'];
        } 
        else if (id === 'MAMLATDAR-SUBIR') {
            query = 'SELECT officialname, phonenumber, email FROM verifyofficals WHERE post = $1';
            queryParam = ['mamlatdar-subir'];
        } 
        else if (id === 'MAMLATDAR-WAGAI') {
            query = 'SELECT officialname, phonenumber, email FROM verifyofficals WHERE post = $1';
            queryParam = ['mamlatdar-wagai'];
        } 
        else if (id === 'SDM') {
            query = 'SELECT officialname, phonenumber, email FROM verifyofficals WHERE post = $1';
            queryParam = ['SDM'];
        } 
        else {
            // If it's a village, check in the `village` column
            query = "SELECT officialname, phonenumber, email FROM verifyofficals WHERE village = $1";
            queryParam = [id.toUpperCase()]; // Convert village name to uppercase for consistency
        }

        // Execute the query
        const result = await pool.query(query, queryParam);

        // Check if the record exists
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Official not found" });
        }

        // Send response
        return res.json(result.rows[0]);

    } catch (error) {
        console.error("Error fetching official details:", error);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});
async function translateSchemeFields(scheme) {
    const apiKey = process.env.OHMG; // 🔐 Replace this
    const endpoint = `https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key=${apiKey}`;
  
    const prompt = `
  Translate the following government scheme details from English to Gujarati. 
  Return ONLY JSON in this format: 
  {
    "schemeName": "...",
    "description": "...",
    "benefits": "...",
    "eligibility": "...",
    "documents": "...",
    "apply": "...",
    "notes": "..."
  }
  
  English Input:
  Scheme Name: ${scheme.schemeName}
  Description: ${scheme.description}
  Benefits: ${scheme.benefits}
  Eligibility: ${scheme.eligibility}
  Documents: ${scheme.documents}
  How to Apply: ${scheme.apply}
  Notes: ${scheme.notes}
  `;
  
    try {
      const response = await axios.post(endpoint, {
        contents: [{ parts: [{ text: prompt }] }],
      }, {
        headers: { "Content-Type": "application/json" },
      });
  
      const output = response.data.candidates[0].content.parts[0].text;
      const start = output.indexOf("{");
      const end = output.lastIndexOf("}");
      const jsonString = output.slice(start, end + 1);
  
      return JSON.parse(jsonString);
    } catch (error) {
      console.error("Gemini Error:", error.response?.data || error.message);
      throw new Error("Gujarati translation failed.");
    }
  }
const cloudinaryStorage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
      folder: "storage", 
      format: async (req, file) => "png",
      public_id: (req, file) => `scheme_${Date.now()}`,
    },
  });
  
  const upload2 = multer({ storage: cloudinaryStorage });
  app.post("/scheme", upload2.single("schemePoster"), async (req, res) => {
    try {
      const {
        schemeName,
        department,
        target,
        description,
        benefits,
        eligibility,
        documents,
        apply,
        lastDate,
        status,
        contact,
        notes,
      } = req.body;
  
      const poster_url = req.file ? req.file.path : null;
  
      // Step 1: Insert English data
      const insertEnglish = `
        INSERT INTO scheme_details 
        (nameofscheme, department, target, description, benefits, eligibility, documents, application, lastdate, status, contact, additional, poster_url)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id;
      `;
  
      const englishValues = [
        schemeName,
        department,
        target,
        description,
        benefits,
        eligibility,
        documents,
        apply,
        lastDate,
        status,
        contact,
        notes,
        poster_url,
      ];
  
      const englishResult = await pool.query(insertEnglish, englishValues);
      const schemeId = englishResult.rows[0].id;
  
      // Step 2: Translate to Gujarati
      const guj = await translateSchemeFields({
        schemeName,
        description,
        benefits,
        eligibility,
        documents,
        apply,
        notes,
      });
  
      // Step 3: Insert Gujarati data
      const insertGujarati = `
        INSERT INTO scheme_details_guj 
        (scheme_id, nameofscheme, description, benefits, eligibility, documents, application, additional, poster_url)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
      `;
  
      const gujValues = [
        schemeId,
        guj.schemeName,
        guj.description,
        guj.benefits,
        guj.eligibility,
        guj.documents,
        guj.apply,
        guj.notes,
        poster_url,
      ];
  
      await pool.query(insertGujarati, gujValues);
  
      res.status(201).json({ message: "Scheme added in English and Gujarati successfully!" });
  
    } catch (error) {
      console.error("Error:", error);
      res.status(500).json({ error: "Something went wrong while adding the scheme." });
    }
  });
  app.get('/api/Gschemes', async (req, res) => {
    try {
      const result = await pool.query('SELECT * FROM scheme_details_guj ORDER BY id DESC');
      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching Gujarati schemes:", error);
      res.status(500).json({ error: 'Gujarati schemes fetch failed' });
    }
  });
  app.get("/api/schemes", async (req, res) => {
    try {
      const result = await pool.query("SELECT * FROM scheme_details ORDER BY lastdate DESC;");
      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching schemes:", error);
      res.status(500).json({ error: "Failed to fetch schemes" });
    }
  });
  app.get('/api/profile/op', async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT officialname, phonenumber, email, post FROM verifyofficals WHERE post = 'Opreator' LIMIT 1"
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Profile not found" });
        }
        res.json({ profile: result.rows[0] });
    } catch (error) {
        console.error("Error fetching profile:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
  app.post('/updatePassword', async (req, res) => {
    const { oldPassword, newPassword } = req.body;
  
    try {
      const checkQuery = `
        SELECT * FROM citizenverify 
        WHERE passwordofcitizen = $1
      `;
      const checkResult = await pool.query(checkQuery, [oldPassword]);
  
      if (checkResult.rowCount === 0) {
        return res.json({ success: false, message: 'Old password is incorrect.' });
      }
  
      const updateQuery = `
        UPDATE citizenverify 
        SET passwordofcitizen = $1 
        WHERE passwordofcitizen = $2
      `;
      await pool.query(updateQuery, [newPassword, oldPassword]);
  
      return res.json({ success: true });
    } catch (error) {
      console.error('Error updating password:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  });
  
  // Route to fetch scheme details by ID
  app.get("/api/schemes/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const result = await pool.query("SELECT * FROM scheme_details WHERE id = $1;", [id]);
  
      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Scheme not found" });
      }
  
      res.json(result.rows[0]);
    } catch (error) {
      console.error("Error fetching scheme details:", error);
      res.status(500).json({ error: "Failed to fetch scheme details" });
    }
  });
  
  // Placeholder for downloading scheme details as a PDF
  app.get("/api/schemes/:id/download", async (req, res) => {
    try {
      const { id } = req.params;
      const result = await pool.query("SELECT * FROM scheme_details WHERE id = $1;", [id]);
  
      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Scheme not found" });
      }
  
      const scheme = result.rows[0];
  
      // For now, send a simple JSON as a placeholder
      res.json({
        message: `Download details for ${scheme.nameofscheme} (PDF generation not implemented yet)`,
        scheme,
      });
  
      // TODO: Implement PDF generation and send it as a file response
    } catch (error) {
      console.error("Error downloading scheme details:", error);
      res.status(500).json({ error: "Failed to download scheme details" });
    }
  });
app.post('/api/update-official', async (req, res) => {
    const { id, name, email, phone } = req.body;

    try {
        if (id === "MAMLATDAR-AHWA") {
            const result = await pool.query(
                "UPDATE verifyofficals SET officialname=$1, phonenumber=$2, email=$3 WHERE post=$4",
                [name, phone, email, "mamlatdar-ahwa"]
            );
            return res.json({ message: "Mamlatdar-Ahwa Updated Successfully" });
        } 
        else if (id === "MAMLATDAR-SUBIR") {
            const result = await pool.query(
                "UPDATE verifyofficals SET officialname=$1, phonenumber=$2, email=$3 WHERE post=$4",
                [name, phone, email, "mamlatdar-subir"]
            );
            return res.json({ message: "Mamlatdar-Subir Updated Successfully" });
        } 
        else if (id === "MAMLATDAR-WAGAI") {
            const result = await pool.query(
                "UPDATE verifyofficals SET officialname=$1, phonenumber=$2, email=$3 WHERE post=$4",
                [name, phone, email, "mamlatdar-wagai"]
            );
            return res.json({ message: "Mamlatdar-Waghai Updated Successfully" });
        } 
        else if (id === "SDM") {
            const result = await pool.query(
                "UPDATE verifyofficals SET officialname=$1, phonenumber=$2, email=$3 WHERE post=$4",
                [name, phone, email, "SDM"]
            );
            return res.json({ message: "SDM Updated Successfully" });
        } 
        else {
            let villageom = id.toUpperCase();
            const result = await pool.query(
                "UPDATE verifyofficals SET officialname=$1, phonenumber=$2, email=$3 WHERE village=$4",
                [name, phone, email, villageom]
            );

            if (result.rowCount === 0) {
                return res.status(404).json({ error: "No matching village record found to update" });
            }

            return res.json({ message: `${villageom} Updated Successfully` });
        }
    } catch (error) {
        console.error("Error updating official details:", error);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});
const upload5 = multer({ storage: storage5 });
app.post('/gmpcomplaint', upload5.single('image'), async (req, res) => {
    try {
        const { name, mobile, taluka, villageCity, complaintCategory, problemDesc } = req.body;

        const imageUrl = req.file ? req.file.path : null;
        const complaintid = `${mobile}-${Date.now()}`;
        const query = `INSERT INTO complaint (department,taluka,mobilenum,nameofcitizen,village,complaintdesc,image_url,ostatus,complaintid) 
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8 ,$9 )`;
        
        const values = [complaintCategory,taluka,mobile,name,villageCity,problemDesc,imageUrl,'Logged',complaintid];
        
        const result = await pool.query(query, values);

        res.status(201).json({ message: 'Complaint filed successfully', data: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
app.post("/signup", async (req, res) => {
    const otp1 = otpGenerator.generate(6, { text: true });
    const { name, phonenumber, email, taluka, district, place, password } = req.body;
    const expiryTime = new Date(Date.now() + 5 * 60 * 1000); 
    const hashPassword = await bcrypt.hash(password, 10);
    
    try {
        await pool.query(
            'INSERT INTO citizenverify (nameofcitizen, phonenumber, email, taluka, district, place, passwordofcitizen, otp, expirytime) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [name, phonenumber, email, taluka, district, place, hashPassword, otp1, expiryTime]
        );
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: "ohmpatel655@gmail.com",
                pass: process.env.GG_PASS,
            },
        });
        const mailOptions = {
            from: 'ohmpatel655@gmail.com',
            to: email,
            subject: 'Verification',
            text: `Your OTP is ${otp1}`,
        };
        await transporter.sendMail(mailOptions);
        res.sendFile(path.join(__dirname, "public", "otp.html"));
    } catch (error) {
        console.error("Error during signup or OTP sending:", error);
        return res.status(500).json({ error: "Error during signup or OTP sending." });
    }
});
app.get("/autofill", async (req, res) => {
    console.log("Request received:", req.query);

    const mobile = req.query.mobile;

    if (!mobile) {
        return res.status(400).json({ error: "Mobile number is required" });
    }

    try {
        const result = await pool.query("SELECT * FROM citizenverify WHERE phonenumber = $1", [mobile]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Citizen not found" });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


app.get("/complaintcard", async (req, res) => {
    try {
        const ostatus1 = "Logged";
        const result = await pool.query(
            'SELECT  department, taluka, complaintdesc, ostatus, complaintid,village, image_url, image_url_proof, proloc, sdate, fdate FROM complaint WHERE ostatus = $1',
            [ostatus1]
        );
        const complaints = result.rows;
        // console.log(complaints);
        let logged = 0;
        complaints.forEach(complaint => {
            if (complaint.ostatus === "Logged") {
                logged++;
            }
        });

        console.log(logged);
        res.json({ complaints, logged });
    } catch (error) {
        console.error("Error fetching complaints:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

  
  app.use(express.static("public"));
  

app.post("/redirect",(req,res)=>{
    // res.sendFile(path.join(__dirname,"public","deapartment.html"));
    res.status(200).json({ message: "Redirect successful" });
});
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const mobile = req.body.mobilenum || 'unknown'; 
        const ext = path.extname(file.originalname);
        cb(null, `${mobile}-${Date.now()}-proof${ext}`);
    }
});
app.use(express.json());
const storage2 = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        return {
            folder: 'grievance_express/proofs',
            resource_type: file.mimetype.startsWith("audio") ? "video" : "image", 
            public_id: `${req.body.mobilenum || 'unknown'}-${Date.now()}`
        };
    }
});

const upload = multer({ storage : storage2 });
app.post('/upload-proof', upload.single('proof'), async(req, res) => {
    try {
        const { mobilenum, complaintdesc, complaintdep,taluka,complaintid} = req.body;
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }
        let department = complaintdep.toLowerCase().replace(/\s+/g, '_');
        const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
        console.log('Uploaded file URL:', fileUrl);
        res.json({
            message: 'Proof uploaded successfully',
            fileUrl,
            mobilenum,
            complaintdesc,
            complaintid
        });
        await pool.query('UPDATE complaint SET ostatus = $1, image_url_proof = $2 WHERE complaintid = $3',['Resolved', fileUrl, complaintid]);
        await pool.query(`UPDATE ${taluka} SET status = $1,image_url_proof=$2 WHERE complaintid = $3`,['Resolved',fileUrl,complaintid]);
        await pool.query(`UPDATE ${department} SET status = $1, image_url_proof = $2 WHERE complaintid = $3`, ['Resolved', fileUrl, complaintid]
);

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});
app.post("/declinecomplaint", async (req, res) => {
    const { complaintid } = req.body;

    if (!complaintid) {
        return res.status(400).json({ error: "Complaint ID is required" });
    }

    try {
        const updateQuery = `
            UPDATE complaint
            SET ostatus = 'Declined' 
            WHERE complaintid = $1
            RETURNING *;
        `;
        const result = await pool.query(updateQuery, [complaintid]);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: "Complaint not found" });
        }

        res.status(200).json({ message: "Complaint declined successfully", complaint: result.rows[0] });
    } catch (error) {
        console.error("Error updating complaint status:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
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
    // return res.json({message:'Done'});
    res.sendFile(path.join(__dirname,"public","citizendashboard.html"));
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
            mobilenum VARCHAR(15),
            status VARCHAR(50),
            image_url_proof VARCHAR(250)
          )
        `;
        await pool.query(createTableSQL);
        const insertDataSQL = `
          INSERT INTO "${tableName}" (complaintdesc, complaintdep, taluka, mobilenum,problemdesc,status)
          VALUES ($1, $2, $3, $4,$5,$6)
        `;
        await pool.query(`INSERT INTO ${complaintInfo.talukaS} (complaintdep,complaintdesc,mobilenum,taluka,complaintcategory,status) VALUES ($1,$2,$3,$4,$5,$6)`,[optionsString,complaintInfo.problemS,complaintInfo.mobilenumS,complaintInfo.talukaS,complaintInfo.complaintS,'Assigned']);
        await pool.query(insertDataSQL, [
          complaintInfo.complaintS,
          optionsString,
          complaintInfo.talukaS,
          complaintInfo.mobilenumS,
          complaintInfo.problemS,
          'Assigned'
        ]);
        console.log("Ohm");
        await pool.query('UPDATE complaint SET ostatus=$1,department =$2 WHERE mobilenum = $3 AND complaintdesc = $4',['Assigned',optionsString,complaintInfo.mobilenumS,complaintInfo.problemS]);
        console.log("OM");
        await pool.query('UPDATE status SET status = $1 WHERE mobilenumber = $2 AND complaint = $3',['Assigned',complaintInfo.mobilenumS,complaintInfo.problemS]);
        await pool.query(`UPDATE ${complaintInfo.talukaS} SET status = $1 WHERE mobilenum = $2 AND complaintdesc = $3`,['Assigned',complaintInfo.mobilenumS,complaintInfo.problemS]);
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
app.post("/dc",async(req,res)=>{
    const ostatus = 'Declined';
    const complaints = await pool.query('SELECT complaint,department,taluka,mobilenum,complaintdesc,image_url FROM complaint WHERE ostatus = $1',[ostatus]);
    res.json(complaints.rows);
});
app.post("/r",async(req,res)=>{
    // const ostatus = '';
    const complaints = await pool.query('SELECT complaint,department,taluka,mobilenum,complaintdesc,image_url FROM complaint',);
    res.json(complaints.rows);
});
app.post("/rc",async(req,res)=>{
    const ostatus = 'Assigned';
    const complaints = await pool.query('SELECT complaint,department,taluka,mobilenum,complaintdesc,image_url FROM complaint WHERE ostatus = $1',[ostatus]);
    res.json(complaints.rows);
});
app.get('/api/complaints/on-hold/:department', async (req, res) => {
    let department = req.params.department.toLowerCase().replace(/\s+/g, '_');
    
    console.log("Requested Department:", department);

    try {
        const result = await pool.query(
            `SELECT * FROM "${department}" WHERE status = $1`, 
            ['On Hold']
        );

        console.log("Query Result:", result.rows);  

        res.json({ complaints: result.rows });

    } catch (error) {
        console.error("Error fetching complaints:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.get('/api/complaints/resolved/:department', async (req, res) => {
    let department = req.params.department.toLowerCase().replace(/\s+/g, '_');
    try {
        const result = await pool.query(
            `SELECT * FROM "${department}" WHERE status = $1`, 
            ['Resolved']
        );
        res.json({ complaints: result.rows });
    } catch (error) {
        console.error("Error fetching complaints:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
app.get('/api/complaints/under-resolution/:department', async (req, res) => {
    const { department } = req.params;
    var department1 = department.toLowerCase().replace(/\s+/g, '_');

    try {
        const result = await pool.query(
            `SELECT * FROM "${department1}" WHERE status = $1`,
            ['Under Resolution']
        );

        res.json({ complaints: result.rows });
    } catch (error) {
        console.error('Error fetching under resolution complaints:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
const ELEVENLABS_API_KEY = process.env.SECERT_KEY;
// const storage1 = multer.diskStorage({
//     destination: (req, file, cb) => {
//         cb(null, 'uploads/audio/'); // Ensure this folder exists
//     },
//     filename: (req, file, cb) => {
//         cb(null, `audio-${Date.now()}.wav`); // Save as .wav file
//     }
// });

// const audioUpload = multer({
//     storage: storage1, // Use the correct variable name
//     fileFilter: (req, file, cb) => {
//         if (!file.mimetype.startsWith('audio/')) {
//             return cb(new Error('Only audio files are allowed!'), false);
//         }
//         cb(null, true);
//     }
// });

// // POST endpoint for audio upload
// app.post('/uploadvoice', audioUpload.single('audio'), async (req, res) => {
//     try {
//         if (!req.file) {
//             throw new Error('No audio file uploaded!');
//         }

//         console.log("File received:", req.file.path); // Debugging

//         // Transcribe the uploaded audio using ElevenLabs API
//         const transcript = await transcribeWithElevenLabs(req.file.path);
//         console.log("Transcription:", transcript);

//         // Process the Gujarati transcript using Gemini API for translation
//         const translatedText = await processGujaratiText(transcript);
//         console.log("Translated Text:", translatedText);

//         res.json({ 
//             message: "Audio uploaded and processed successfully!", 
//             filePath: req.file.path,
//             transcript,
//             translatedText 
//         });

//     } catch (error) {
//         console.error("Error:", error.message);
//         res.status(500).json({ error: error.message });
//     }
// });
app.get('/api/complaint-coordinator', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT  officialname, email, phonenumber, post FROM verifyofficals WHERE post = $1',
            ['Opreator']
        );

        res.json(result.rows); 
    } catch (err) {
        console.error('Error fetching complaint coordinators:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
app.get('/api/profile/gmp', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT officialname AS name, phonenumber AS phone, email, post 
             FROM verifyofficials WHERE post = $1`, 
            ['grampanchayat']
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Profile not found" });
        }

        res.json(result.rows[0]);
    } catch (err) {
        console.error("Error fetching GMP profile:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// 📝 Update GMP Official Profile
app.put('/api/profile/gmp/update', async (req, res) => {
    const { name, phone, email } = req.body;

    try {
        const result = await pool.query(
            `UPDATE verifyofficials 
             SET officialname = $1, phonenumber = $2, email = $3 
             WHERE post = $4 RETURNING officialname AS name, phonenumber AS phone, email, post`,
            [name, phone, email, 'grampanchayat']
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Profile not found" });
        }

        res.json({ message: "Profile updated successfully", updatedProfile: result.rows[0] });
    } catch (err) {
        console.error("Error updating GMP profile:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.post("/api/submit-suggestion" ,async(req,res)=>{
    const {suggestionText} = req.body;
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
            to: "ohmpatel655@gmail.com",
            subject: "Suggestion",
            text: suggestionText,
        };

        await transporter.sendMail(mailOptions);
        console.log('done');
    } catch (error) {
        console.error("Error sending Suggestion:", suggestion);
        return res.status(500).json({ error: "Error sending Suggestion." });
    }
});
// 🔒 Change GMP Password
app.put('/api/profile/gmp/changepassword', async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    try {
        // 1. Get existing password
        const userRes = await pool.query(
            'SELECT passwordoff FROM verifyofficials WHERE post = $1',
            ['grampanchayat']
        );

        if (userRes.rows.length === 0) {
            return res.status(404).json({ message: "GMP official not found" });
        }

        const hashedPassword = userRes.rows[0].passwordoff;

        // 2. Compare old password
        const isMatch = await bcrypt.compare(oldPassword, hashedPassword);
        if (!isMatch) {
            return res.status(401).json({ message: "Incorrect old password" });
        }

        // 3. Hash new password
        const newHashed = await bcrypt.hash(newPassword, 10);

        // 4. Update new password
        await pool.query(
            'UPDATE verifyofficials SET passwordoff = $1 WHERE post = $2',
            [newHashed, 'grampanchayat']
        );

        res.json({ message: "Password updated successfully" });
    } catch (err) {
        console.error("Error changing GMP password:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});
// API to fetch Mamlatdar profile
app.get('/api/profile/mamlatdar', async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT officialname, phonenumber, email, post FROM verifyofficals WHERE post = 'mamlatdar-ahwa' LIMIT 1"
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Profile not found" });
        }
        res.json({ profile: result.rows[0] });
    } catch (error) {
        console.error("Error fetching profile:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.get("/api/profile/admin", async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT officialname, post, email, phonenumber FROM verifyofficals WHERE post=$1',
            ['Collector']
        );
        console.log(result.rows[0]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Admin not found" });
        }
        return res.json(result.rows[0]);
    } catch (err) {
        console.error("Error fetching admin profile:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Make sure you have this route properly defined in your backend
app.post('/api/sdm/profile/update', async (req, res) => {
    try {
        const { officialName, email, contact } = req.body;
        
        // Validate inputs
        if (!officialName || !email || !contact) {
            return res.status(400).json({ error: "All fields are required" });
        }

        // Update database
        const result = await pool.query(
            'UPDATE verifyofficals SET officialname = $1, email = $2, phonenumber = $3 WHERE phonenumber = $4 RETURNING *',
            [officialName, email, contact, contact]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: "Profile not found" });
        }

        res.json({
            success: true,
            message: "Profile updated successfully",
            profile: result.rows[0]
        });
    } catch (error) {
        console.error("Profile update error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.get('/api/complaints/sdm/pending-old', async (req, res) => {
    try {
        const query = `
            SELECT * FROM complaint
            WHERE ostatus = 'Assigned'
            AND sdate < CURRENT_DATE - INTERVAL '15 days'
            ORDER BY sdate ASC;
        `;

        const result = await pool.query(query);
        res.json({ complaints: result.rows });
    } catch (err) {
        console.error("Error fetching old unresolved complaints:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.get("/api/sdm/profile", async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT officialname, phonenumber, post, email FROM verifyofficals WHERE post = $1 LIMIT 1',
            ['SDM']
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'SDM profile not found' });
        }

        const sdmProfile = result.rows[0];

        res.json(sdmProfile);
    } catch (error) {
        console.error('Error fetching SDM profile:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/api/profile', async (req, res) => {
    const { department } = req.query;
    if (!department) return res.status(400).json({ error: 'Department is required' });

    try {
        const result = await pool.query(
            'SELECT * FROM verifyofficals WHERE post = $1',
            [department]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });

        const profile = result.rows[0];
        return res.json({
            post: profile.post,
            officialname: profile.officialname,
            phonenumber: profile.phonenumber,
            email: profile.email
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
app.post('/api/profile/update', async (req, res) => {
    const { department, hod, contact, email } = req.body;
    if (!department || !hod || !contact || !email)
        return res.status(400).json({ error: 'Missing fields' });

    try {
        await pool.query(
            'UPDATE verifyofficals SET officialname = $1, phonenumber = $2, email = $3 WHERE post = $4',
            [hod, contact, email, department]
        );
        res.json({ message: 'Profile updated' });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
app.post('/api/profile/change-password', async (req, res) => {
    const { post, oldPassword, newPassword } = req.body;
    if (!post || !oldPassword || !newPassword)
        return res.status(400).json({ error: 'Missing fields' });

    try {
        const result = await pool.query(
            'SELECT passwordoff FROM verifyofficals WHERE post = $1',
            [post]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });

        const match = await bcrypt.compare(oldPassword, result.rows[0].passwordoff);
        if (!match) return res.status(401).json({ error: 'Old password incorrect' });

        const hashed = await bcrypt.hash(newPassword, 10);
        await pool.query(
            'UPDATE verifyofficals SET passwordoff = $1 WHERE post = $2',
            [hashed, post]
        );
        res.json({ message: 'Password changed' });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
// Function to transcribe audio using ElevenLabs API
async function transcribeWithElevenLabs(audioUrl) {
    try {
        // ✅ Step 1: Download the audio from Cloudinary
        const response = await axios.get(audioUrl, { responseType: "arraybuffer" });
        const audioBuffer = Buffer.from(response.data);

        // ✅ Step 2: Convert Buffer to Stream
        const stream = new Readable();
        stream.push(audioBuffer);
        stream.push(null);

        // ✅ Step 3: Prepare FormData
        const formData = new FormData();
        formData.append("file", stream, {
            filename: "audio.wav",
            contentType: "audio/wav"
        });
        formData.append("model", "whisper-1");
        formData.append("model_id", "scribe_v1");
        formData.append("language", "gu");

        // ✅ Step 4: Send request to ElevenLabs API
        const elevenLabsResponse = await axios.post(
            "https://api.elevenlabs.io/v1/speech-to-text",
            formData,
            {
                headers: {
                    "xi-api-key": ELEVENLABS_API_KEY,
                    ...formData.getHeaders()
                }
            }
        );
        console.log("🎤 ElevenLabs Response:", elevenLabsResponse.data);
        return elevenLabsResponse.data.text || "Transcription failed";
    } catch (error) {
        console.error("❌ ElevenLabs API error:", error.response ? error.response.data : error.message);
        return "Error in speech-to-text conversion";
    }
}
async function processGujaratiText(transcript) {
    const apikey = process.env.OHMG;
    const url = `https://generativelanguage.googleapis.com/v1/models/gemini-1.5-pro-001:generateContent?key=${apikey}`;

    const requestBody = {
        contents: [{
            parts: [{ text: `Provide me a single paragraph which is the English translate of the following (note: don't include the meanings separately, just let it be a single para): ${transcript}` }]
        }]
    };

    try {
        const response = await axios.post(url, requestBody, {
            headers: { "Content-Type": "application/json" }
        });

        console.log("✅ Full API Response:", response.data); 
        const translatedText = response.data.candidates[0].content.parts[0].text;
        console.log("✅ Translated Text:", translatedText); 

        return translatedText; 
    } catch (error) {
        console.error("❌ Gemini API error:", error.response ? error.response.data : error.message);
        throw new Error("Translation failed.");
    }
}

app.get("/api/complaints/admin", async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM complaint');
        res.json(result.rows); 
    } catch (error) {
        console.error("Error fetching complaints:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
app.get('/api/complaints/taluka/urgent', async (req, res) => {
    try {
        const currentDate = new Date();
        const result = await pool.query(
            `SELECT * FROM complaint WHERE taluka = $1`,
            ['Ahwa'] 
        );
        const complaints = result.rows
            .map(complaint => {
                const complaintDate = new Date(complaint.complaint_date);
                const daysAgo = Math.floor((currentDate - complaintDate) / (1000 * 60 * 60 * 24));
                return { ...complaint, daysAgo };
            })
            .filter(complaint => complaint.daysAgo > 7);

        res.status(200).json(complaints);
    } catch (error) {
        console.error("Error fetching urgent complaints:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.get('/api/complaints/sdm/urgent', async (req, res) => {
    try {
        const currentDate = new Date();
        const result = await pool.query(
            `SELECT * FROM complaint `
        );

        const complaints = result.rows
            .map(complaint => {
                const complaintDate = new Date(complaint.complaint_date);
                const daysAgo = Math.floor((currentDate - complaintDate) / (1000 * 60 * 60 * 24));
                return { ...complaint, daysAgo };
            })
            .filter(complaint => complaint.daysAgo > 15);

        res.status(200).json(complaints);
    } catch (error) {
        console.error("Error fetching urgent SDM complaints:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get('/api/departments', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name, officialname, phone, email FROM verifyofficals');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});
app.get('/api/get-department/:id', async (req, res) => {
        const departmentId = req.params.id.replace(/-/g, '_');

    console.log('Incoming request for department:', departmentId);

    try {
        const result = await pool.query(
            'SELECT post, officialname, phonenumber, email FROM verifyofficals WHERE LOWER(post) = LOWER($1)',
            [departmentId]
        );

        const department = result.rows[0];

        if (!department) {
            console.log('No department found for:', departmentId);
            return res.status(404).json({ error: 'Department not found' });
        }

        console.log('Department found:', department);

        res.json({
            name: department.post,
            officialname: department.officialname,
            phone: department.phonenumber,
            email: department.email
        });
    } catch (error) {
        console.error('❌ Error fetching department:', error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/decline-by-me',async(req,res)=>{
    const {complaintid}= req.body;
    await pool.query('UPDATE complaint SET ostatus = $1 WHERE complaintid = $2', ['Logged',complaintid]);
    await pool.query('DELETE FROM water_supply WHERE complaintid = $1', [complaintid]);
});
app.get('/api/complaints/pending-30-days/count', async (req, res) => {
    try {
        const currentDate = new Date();

        const result = await pool.query(`SELECT * FROM complaint WHERE ostatus = 'Assigned'`);

        const complaints = result.rows
            .map(complaint => {
                const createdDate = new Date(complaint.complaint_date);
                const daysPending = Math.floor((currentDate - createdDate) / (1000 * 60 * 60 * 24));
                return { ...complaint, daysPending };
            })
            .filter(complaint => complaint.daysPending > 30);

        res.status(200).json({ complaints });
    } catch (error) {
        console.error("Error fetching 30+ days pending complaints:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post('/api/add-department', async (req, res) => {
    try {
        const { id, name, officialname, phone, email, password } = req.body;
        // const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await pool.query(
            `INSERT INTO verifyofficals (post, officialname, phonenumber, email, passwordoff)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING  post, officialname, phone, email`,
            [ name, officialname, phone, email, password]
        );
        
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Update department
app.post('/api/update-department', async (req, res) => {
    try {
        const {name, officialname, phone, email, password } = req.body;
        let query, params;
        
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query = `
                UPDATE verifyofficals 
                SET  officialname = $1, phonenumber = $2, email = $3, passwordoff = $4
                WHERE post = $5
                RETURNING post, officialname, phonenumber, email
            `;
            params = [officialname, phone, email, hashedPassword, name];
        } else {
            query = `
                UPDATE verifyofficals 
                SET  officialname = $1, phonenumber = $2, email = $3
                WHERE post = $4
                RETURNING post, officialname, phonenumber, email
            `;
            params = [ officialname, phone, email, name];
        }

        const result = await pool.query(query, params);
        
        if (result.rows[0].length === 0) {
            return res.status(404).json({ message: 'Department not found' });
        }
        
        res.json(result.rows[0]);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Delete department
app.post('/api/delete-department/:id', async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM verifyofficals WHERE id = $1 RETURNING id',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Department not found' });
        }
        
        res.json({ message: 'Department deleted' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});
app.post('/api/delete-official/:id', async (req, res) => {
    const officialId = req.params.id;

    try {
        const result = await pool.query(
            'DELETE FROM verifyofficals WHERE post = $1 RETURNING *',
            [officialId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Official not found' });
        }

        res.status(200).json({ message: 'Official deleted successfully' });
    } catch (error) {
        console.error('Error deleting official:', error);
        res.status(500).json({ message: 'Failed to delete official' });
    }
});
app.post("/api/add-village", async (req, res) => {
    const { name, officialname, phone, email, password } = req.body;
    
    try {
        // Corrected SQL query
        await pool.query(
            'INSERT INTO verifyofficals (village, officialname, phonenumber, email, passwordoff, post) VALUES ($1, $2, $3, $4, $5, $6)',
            [name, officialname, phone, email, password, 'TALATI']
        );
        res.status(201).json({ message: 'Village official added successfully!' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Failed to add village official' });
    }
});
app.get("/api/villages", async (req, res) => {
  try {
    const query = `
            SELECT 
                v.id,
                v.name as village_name,
                v.secretary_name,
                v.phone,
                v.email,
                t.name as taluka_name,
                t.id as taluka_id
            FROM villages v
            JOIN talukas t ON v.taluka_id = t.id
            ORDER BY t.name, v.name
        `

    const result = await pool.query(query)

    // Group villages by taluka
    const villagesByTaluka = {}
    result.rows.forEach((row) => {
      if (!villagesByTaluka[row.taluka_name]) {
        villagesByTaluka[row.taluka_name] = []
      }
      villagesByTaluka[row.taluka_name].push({
        id: row.id,
        name: row.village_name,
        secretary_name: row.secretary_name,
        phone: row.phone,
        email: row.email,
        taluka_id: row.taluka_id,
      })
    })

    res.json({
      success: true,
      data: villagesByTaluka,
    })
  } catch (error) {
    console.error("Error fetching villages:", error)
    res.status(500).json({
      success: false,
      error: "Failed to fetch villages",
    })
  }
})

// POST /api/villages - Add new village
app.post("/api/villages", async (req, res) => {
  try {
    const { name, taluka_name, secretary_name, phone, email, password } = req.body

    if (!name || !taluka_name) {
      return res.status(400).json({
        success: false,
        error: "Village name and taluka are required",
      })
    }

    // Get taluka ID
    const talukaQuery = "SELECT id FROM talukas WHERE name = $1"
    const talukaResult = await pool.query(talukaQuery, [taluka_name])

    if (talukaResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Taluka not found",
      })
    }

    const taluka_id = talukaResult.rows[0].id

    // Insert new village
    const insertQuery = `
            INSERT INTO villages (name, taluka_id, secretary_name, phone, email, password)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
        `

    const insertResult = await pool.query(insertQuery, [
      name,
      taluka_id,
      secretary_name || "",
      phone || "",
      email || "",
      password || "",
    ])

    res.json({
      success: true,
      data: {
        id: insertResult.rows[0].id,
        name,
        taluka_name,
        secretary_name,
        phone,
        email,
      },
    })
  } catch (error) {
    console.error("Error adding village:", error)
    if (error.code === "23505") {
      return res.status(409).json({
        success: false,
        error: "Village already exists in this taluka",
      })
    }
    res.status(500).json({
      success: false,
      error: "Failed to add village",
    })
  }
})

// GET /api/villages/:id - Fetch single village
app.get("/api/villages/:id", async (req, res) => {
  try {
    const { id } = req.params

    const query = `
            SELECT 
                v.id,
                v.name as village_name,
                v.secretary_name,
                v.phone,
                v.email,
                t.name as taluka_name,
                t.id as taluka_id
            FROM villages v
            JOIN talukas t ON v.taluka_id = t.id
            WHERE v.id = $1
        `

    const result = await pool.query(query, [id])

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Village not found",
      })
    }

    res.json({
      success: true,
      data: result.rows[0],
    })
  } catch (error) {
    console.error("Error fetching village:", error)
    res.status(500).json({
      success: false,
      error: "Failed to fetch village",
    })
  }
})

// PUT /api/villages/:id - Update village
app.put("/api/villages/:id", async (req, res) => {
  try {
    const { id } = req.params
    const { name, secretary_name, phone, email, password } = req.body

    if (!name) {
      return res.status(400).json({
        success: false,
        error: "Village name is required",
      })
    }

    // Build update query
    let updateQuery =
      "UPDATE villages SET name = $1, secretary_name = $2, phone = $3, email = $4, updated_at = CURRENT_TIMESTAMP"
    const queryParams = [name, secretary_name || "", phone || "", email || ""]

    if (password) {
      updateQuery += ", password = $5 WHERE id = $6"
      queryParams.push(password, id)
    } else {
      updateQuery += " WHERE id = $5"
      queryParams.push(id)
    }

    const result = await pool.query(updateQuery, queryParams)

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        error: "Village not found",
      })
    }

    res.json({
      success: true,
      message: "Village updated successfully",
    })
  } catch (error) {
    console.error("Error updating village:", error)
    res.status(500).json({
      success: false,
      error: "Failed to update village",
    })
  }
})

// DELETE /api/villages/:id - Delete village
app.delete("/api/villages/:id", async (req, res) => {
  try {
    const { id } = req.params

    const deleteQuery = "DELETE FROM villages WHERE id = $1"
    const result = await pool.query(deleteQuery, [id])

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        error: "Village not found",
      })
    }

    res.json({
      success: true,
      message: "Village deleted successfully",
    })
  } catch (error) {
    console.error("Error deleting village:", error)
    res.status(500).json({
      success: false,
      error: "Failed to delete village",
    })
  }
})

// GET /api/talukas - Fetch all talukas
app.get("/api/talukas", async (req, res) => {
  try {
    const query = "SELECT id, name FROM talukas ORDER BY name"
    const result = await pool.query(query)

    res.json({
      success: true,
      data: result.rows,
    })
  } catch (error) {
    console.error("Error fetching talukas:", error)
    res.status(500).json({
      success: false,
      error: "Failed to fetch talukas",
    })
  }
})
app.post('/api/register-cc', async (req, res) => {
    const { name, email, mobile, password } = req.body;

    // Basic validation
    if (!name || !email || !mobile || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        const result = await pool.query(
            'UPDATE verifyofficals SET officialname = $1, email = $2, phonenumber = $3, passwordoff = $4 WHERE post = $5',
            [name, email, mobile, password, 'Operator']
        );
        res.status(201).json({ message: 'Registration successful.' });
    } catch (error) {
        console.error('Error in /api/register-cc:', error);
        res.status(500).json({ message: 'Server error. Try again later.' });
    }
});

const PORT1 = process.env.PORT || 3000;
app.listen(3000, () => {
    console.log(`Server is running at http://localhost:3000`);
  }).on("error", (err) => {
    console.error("Error:", err);
  });
