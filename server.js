require("dotenv").config();
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

server.listen(5000, () => console.log("Server is running on port 5000"));




/*require("dotenv").config();

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  

.then(() => console.log("Connected to MongoDB Atlas"))
.catch((err) => console.error("MongoDB connection error:", err));


const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] },
});

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
    jwt.verify(token, "SECRET_KEY", (err, user) => {
        if (err) return res.status(403).send("Invalid Token");
        req.user = user;
        next();
    });
};

app.post("/signup", async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.status(201).send("User registered successfully");
    } catch (err) {
        res.status(400).send("Error registering user");
    }
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).send("User not found");
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).send("Invalid credentials");
    const token = jwt.sign({ username, profilePicture: user.profilePicture }, "SECRET_KEY", { expiresIn: "1h" });
    res.json({ token });
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
            // Store the message in the receiver's chat
            await User.updateOne({ username: receiver }, { $push: { chats: chatMessage } });

            // Emit the message only to the receiver's room
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