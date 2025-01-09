const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "https://chat-app-adarsh.vercel.app",
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
});
