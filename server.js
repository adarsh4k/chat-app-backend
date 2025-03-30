require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

// Environment variables validation
if (!process.env.MONGO_URI || !process.env.JWT_SECRET) {
    throw new Error("Missing required environment variables");
}

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("Connected to MongoDB Atlas"))
    .catch((err) => console.error("MongoDB connection error:", err));

const app = express();
const server = http.createServer(app);

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// CORS configuration
const corsOptions = {
    origin: process.env.FRONTEND_URL || "https://chat-app-adarsh.vercel.app/",
    methods: ["GET", "POST"]
};
const io = new Server(server, { cors: corsOptions });

app.use(cors(corsOptions));
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// Schemas
const userSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true,
        minlength: 3,
        maxlength: 20,
        match: /^[a-zA-Z0-9_]+$/ // Alphanumeric with underscores
    },
    password: { 
        type: String, 
        required: true,
        minlength: 8
    },
    profilePicture: { type: String },
    lastSeen: { type: Date }
});

const messageSchema = new mongoose.Schema({
    sender: { type: String, required: true },
    receiver: { type: String, required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    read: { type: Boolean, default: false }
});

const User = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);

// Middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Authentication required" });
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid or expired token" });
        req.user = user;
        next();
    });
};

const validateInput = (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required" });
    }
    if (username.length < 3 || username.length > 20) {
        return res.status(400).json({ error: "Username must be 3-20 characters" });
    }
    if (password.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters" });
    }
    next();
};

// Routes
app.post("/signup", validateInput, async (req, res) => {
    try {
        const { username, password } = req.body;

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: "Username already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();

        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        console.error("Signup error:", err);
        res.status(500).json({ error: "Could not complete registration" });
    }
});

app.post("/login", validateInput, async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        // Update last seen
        await User.updateOne({ username }, { lastSeen: new Date() });

        const token = jwt.sign(
            { username, profilePicture: user.profilePicture },
            process.env.JWT_SECRET,
            { expiresIn: "24h" }
        );
        
        res.json({ token });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "Login failed" });
    }
});

app.get("/users", authenticateToken, async (req, res) => {
    try {
        const users = await User.find(
            { username: { $ne: req.user.username } },
            "username profilePicture lastSeen"
        );
        res.json(users);
    } catch (err) {
        console.error("Users fetch error:", err);
        res.status(500).json({ error: "Could not fetch users" });
    }
});

app.get("/chats/:username", authenticateToken, async (req, res) => {
    try {
        const messages = await Message.find({
            $or: [
                { sender: req.user.username, receiver: req.params.username },
                { sender: req.params.username, receiver: req.user.username }
            ]
        }).sort({ timestamp: 1 });
        
        res.json(messages);
    } catch (err) {
        console.error("Chat fetch error:", err);
        res.status(500).json({ error: "Could not fetch chat history" });
    }
});

// Socket.io
io.on("connection", (socket) => {
    console.log("New user connected");

    socket.on("join_room", async (username) => {
        socket.join(username);
        console.log(`${username} joined their room`);
        
        // Update last seen when user connects
        await User.updateOne({ username }, { lastSeen: new Date() });
    });

    socket.on("send_message", async (data) => {
        try {
            const { sender, receiver, content } = data;
            
            // Validate input
            if (!sender || !receiver || !content) {
                throw new Error("Missing required fields");
            }
            if (content.length > 1000) {
                throw new Error("Message too long");
            }

            // Save message to database
            const newMessage = new Message({
                sender,
                receiver,
                content,
                timestamp: new Date()
            });
            await newMessage.save();

            // Emit to receiver
            io.to(receiver).emit("receive_message", newMessage);
            
            // Also emit back to sender for UI update
            io.to(sender).emit("receive_message", newMessage);
        } catch (err) {
            console.error("Message send error:", err);
        }
    });

    socket.on("mark_as_read", async ({ messageIds, sender, receiver }) => {
        try {
            await Message.updateMany(
                { _id: { $in: messageIds }, sender, receiver, read: false },
                { $set: { read: true } }
            );
            io.to(sender).emit("messages_read", { messageIds });
        } catch (err) {
            console.error("Mark as read error:", err);
        }
    });

    socket.on("disconnect", () => {
        console.log("User disconnected");
    });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));


/*require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("Connected to MongoDB Atlas"))
    .catch((err) => console.error("MongoDB connection error:", err));

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    profilePicture: { type: String },
    chats: [{ type: mongoose.Schema.Types.Mixed }],
});

const User = mongoose.model("User", userSchema);

const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).send("Access Denied");
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send("Invalid Token");
        req.user = user;
        next();
    });
};

app.post("/signup", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).send("Username and password are required");

        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).send("Username already exists");

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();

        res.status(201).send("User registered successfully");
    } catch (err) {
        res.status(500).send("Error registering user");
    }
});

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(400).send("User not found");

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(400).send("Invalid credentials");

        const token = jwt.sign({ username, profilePicture: user.profilePicture }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token });
    } catch (err) {
        res.status(500).send("Login error");
    }
});

app.get("/users", authenticateToken, async (req, res) => {
    const users = await User.find({}, "username profilePicture");
    res.json(users);
});

app.get("/chats/:username", authenticateToken, async (req, res) => {
    const user = await User.findOne({ username: req.params.username });
    if (!user) return res.status(404).send("User not found");
    res.json(user.chats || []);
});

io.on("connection", (socket) => {
    console.log("A user connected");

    socket.on("join_room", (username) => {
        socket.join(username);
        console.log(`${username} joined their room`);
    });

    
   
    
   socket.on("send_message", async (data) => {
        const { sender, receiver, message, timestamp } = data;
        const chatMessage = { sender, message, timestamp };

        try {
            await User.updateOne({ username: receiver }, { $push: { chats: chatMessage } });
            await User.updateOne({ username: sender }, { $push: { chats: chatMessage } });

            io.to(receiver).emit("receive_message", chatMessage);
        } catch (err) {
            console.error("Error saving chat:", err);
        }
    });

    socket.on("disconnect", () => {
        console.log("A user disconnected");
    });
});

server.listen(5000, () => console.log("Server is running on port 5000"));*/




