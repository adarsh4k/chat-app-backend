const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");

const app = express();
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "https://chat-app-adarsh.vercel.app", 
        methods: ["GET", "POST"],
    },
});

let typingUsers = new Set();

io.on("connection", (socket) => {
    console.log("A user connected:", socket.id);

    
    socket.on("set_username", (data) => {
        socket.username = data.username;
        socket.profilePicture = data.profilePicture;
        console.log(`User set their username: ${data.username}`);
    });

    
    socket.on("send_message", (data) => {
        const messageData = {
            username: data.username,
            profilePicture: data.profilePicture,
            message: data.message,
            timestamp: data.timestamp,
        };
        io.emit("receive_message", messageData);
    });


    socket.on("user_typing", (data) => {
        if (data.isTyping) {
            typingUsers.add(data.username);
        } else {
            typingUsers.delete(data.username);
        }

        io.emit("user_typing", { username: data.username, isTyping: data.isTyping });
    });

    socket.on("disconnect", () => {
        console.log("A user disconnected:", socket.id);
        typingUsers.delete(socket.username);
    });
});

server.listen(5000, () => {
    console.log("Server is running on port 5000");
});














/*const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ['GET', 'POST'],
    },
});

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);
    socket.on('set_username', (username) => {
        socket.username = username;
    });
    socket.on('send_message', (message) => {
        
        io.emit('receive_message', { username: socket.username, message});
    });

    socket.on('disconnect', () => {
        console.log('A user disconnected:', socket.id);
    });
   
    
});
app.get('/', (req, res) => {
    res.send('Backend is running!');
});




const PORT = 5000;
server.listen(PORT, "0.0.0.0",() => {
    console.log(`Server running on http://localhost:${PORT}`);
});*/
