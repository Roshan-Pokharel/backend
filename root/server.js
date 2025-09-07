const express = require("express");
require("dotenv").config();
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { randomUUID } = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { connectToDb } = require("./database");
const { ObjectId } = require("mongodb");

const app = express();
const server = http.createServer(app);

const JWT_SECRET = process.env.JWT_SECRET;
const corsOptions = {
  origin: "*",
  methods: ["GET", "POST"],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10mb" })); // Increase limit for profile pictures

const io = new Server(server, {
  cors: corsOptions,
});

let db;
let usersCollection;
let messagesCollection;
let activeChatsCollection;
let groupsCollection; // New collection for groups

// --- STATE MANAGEMENT ---
const users = {};
const gameStates = {};
let activeGameRooms = {};
const pendingPrivateRequests = {};
const declinedChats = new Set();
const callStates = {};
const roomMessageCache = {};
const userIdToSocketId = {};
const activeGroupCalls = {}; // { groupId: { socketId1, socketId2, ... } }

async function initializeDb() {
  db = await connectToDb();
  usersCollection = db.collection("users");
  messagesCollection = db.collection("messages");
  activeChatsCollection = db.collection("active_chats");
  groupsCollection = db.collection("groups"); // Initialize group collection

  try {
    const publicHistory = await messagesCollection
      .find({ room: "public" })
      .sort({ timestamp: -1 })
      .limit(50)
      .toArray();
    roomMessageCache["public"] = publicHistory.reverse();
    console.log("✅ Public chat history cached.");
  } catch (err) {
    console.error("🔴 Error caching public chat history:", err);
  }
}

// --- GAME CONSTANTS and RATE LIMITING ---
const DOODLE_WORDS = [
  "apple",
  "banana",
  "car",
  "house",
  "tree",
  "star",
  "sun",
  "moon",
  "dog",
  "cat",
  "bird",
  "fish",
  "flower",
  "cloud",
  "boat",
  "train",
  "book",
  "key",
  "hat",
  "shoe",
];
const HANGMAN_WORDS = [
  "javascript",
  "html",
  "css",
  "nodejs",
  "react",
  "angular",
  "vue",
  "mongodb",
  "express",
  "socket",
  "token",
  "server",
];
const DOODLE_ROUND_TIME = 60 * 1000;
const HANGMAN_TURN_TIME = 20 * 1000;
const WINNING_SCORE = 10;
const MAX_INCORRECT_GUESSES = 6;
const userMessageTimestamps = {};
const RATE_LIMIT_COUNT = 5;
const RATE_LIMIT_SECONDS = 5;

// --- API Endpoints for Auth ---
app.post("/register", async (req, res) => {
  const { username, password, profilePicture } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }
  try {
    const existingUser = await usersCollection.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      username,
      password: hashedPassword,
      profilePicture: profilePicture || null,
      createdAt: new Date(),
    };
    await usersCollection.insertOne(newUser);
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }
  try {
    const user = await usersCollection.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const token = jwt.sign(
      {
        userId: user._id.toString(),
        username: user.username,
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// --- Middleware for authenticating API requests ---
const protectApi = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res
          .status(401)
          .json({ message: "Not authorized, token failed" });
      }
      req.user = decoded; // Add user payload to request
      next();
    });
  } else {
    res.status(401).json({ message: "Not authorized, no token" });
  }
};

app.post("/update-profile", protectApi, async (req, res) => {
  const { profilePicture } = req.body;
  const userId = req.user.userId;

  if (typeof profilePicture !== "string") {
    return res.status(400).json({ message: "Invalid profile picture data." });
  }

  try {
    // Step 1: Update the database
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: { profilePicture: profilePicture } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    // Step 2: Update the in-memory state for the active user if they are online
    const socketId = userIdToSocketId[userId];
    if (socketId && users[socketId]) {
      users[socketId].profilePicture = profilePicture;
    }

    // Step 3: Notify all clients about the updated picture
    io.emit("user profile updated", { userId, profilePicture });

    res.status(200).json({ message: "Profile updated successfully" });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ message: "Server error while updating profile" });
  }
});

// --- UTILITY FUNCTIONS ---
function getPublicRoomList() {
  return Object.values(activeGameRooms).map((room) => ({
    id: room.id,
    name: room.name,
    creatorName: room.creatorName,
    players: room.players,
    hasPassword: !!room.password,
    inProgress: room.inProgress || false,
    gameType: room.gameType,
  }));
}

function handlePlayerLeave(socketId, roomId) {
  const room = activeGameRooms[roomId];
  if (!room) return;
  const playerIndex = room.players.findIndex((p) => p.id === socketId);
  if (playerIndex === -1) return;
  const departingPlayer = room.players[playerIndex];
  room.players.splice(playerIndex, 1);
  io.to(roomId).emit("chat message", {
    room: roomId,
    text: `${departingPlayer.name} has left the game.`,
    name: "System",
  });
  const gameState = gameStates[roomId];
  const minPlayers = room.gameType === "doodle" ? 2 : 2;
  if (room.players.length < minPlayers) {
    if (gameState && gameState.isRoundActive) {
      if (gameState.roundTimer) clearTimeout(gameState.roundTimer);
      if (gameState.turnTimer) clearTimeout(gameState.turnTimer);
      io.to(roomId).emit(
        "game:message",
        "Not enough players. The game has ended."
      );
      io.to(roomId).emit("game:terminated", "Not enough players to continue.");
    }
    delete activeGameRooms[roomId];
    delete gameStates[roomId];
  } else {
    if (room.creatorId === socketId) {
      room.creatorId = room.players[0].id;
      room.creatorName = room.players[0].name;
      io.to(roomId).emit(
        "game:message",
        `${room.creatorName} is the new host.`
      );
    }
    if (gameState && gameState.isRoundActive) {
      if (room.gameType === "doodle" && gameState.drawer.id === socketId) {
        io.to(roomId).emit(
          "game:message",
          "The drawer left. Starting a new round."
        );
        clearTimeout(gameState.roundTimer);
        startNewDoodleRound(roomId);
      } else if (
        room.gameType === "hangman" &&
        gameState.currentPlayerTurn === socketId
      ) {
        io.to(roomId).emit(
          "game:message",
          "A player left. The Hangman game has ended."
        );
        io.to(roomId).emit(
          "game:terminated",
          "A player left, ending the game."
        );
        delete activeGameRooms[roomId];
        delete gameStates[roomId];
      }
    }
    if (gameState) {
      io.to(roomId).emit("game:state", {
        ...gameState,
        players: room.players,
        creatorId: room.creatorId,
      });
    }
  }
  io.emit("game:roomsList", getPublicRoomList());
}

async function startServer() {
  // Wait for the database to be ready
  await initializeDb();

  // Socket.IO Middleware for JWT authentication
  io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error("Authentication error"));
    }
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return next(new Error("Authentication error: Invalid token"));
      }
      socket.user = decoded;
      next();
    });
  });

  // --- SOCKET.IO CONNECTION ---
  io.on("connection", async (socket) => {
    const userId = socket.user.userId;

    let freshUserData;
    try {
      freshUserData = await usersCollection.findOne({
        _id: new ObjectId(userId),
      });
    } catch (e) {
      console.error("Error fetching user data on connection:", e);
      socket.disconnect();
      return;
    }

    if (!freshUserData) {
      console.error(`User with ID ${userId} not found in database.`);
      socket.disconnect();
      return;
    }

    if (userIdToSocketId[userId]) {
      const oldSocketId = userIdToSocketId[userId];
      const oldSocket = io.sockets.sockets.get(oldSocketId);
      if (oldSocket) {
        oldSocket.disconnect(true);
      }
      delete users[oldSocketId];
    }

    console.log("🟢 User connected:", socket.id, socket.user.username);

    userMessageTimestamps[socket.id] = [];
    callStates[socket.id] = { status: "idle", partnerId: null };
    userIdToSocketId[userId] = socket.id;
    users[socket.id] = {
      id: socket.id,
      userId: userId,
      name: socket.user.username,
      profilePicture: freshUserData.profilePicture,
    };

    socket.join("public");

    // Fetch user's groups
    const userGroups = await groupsCollection
      .find({ members: userId })
      .toArray();
    userGroups.forEach((group) => socket.join(`group-${group._id}`));

    // Fetch active private chats
    const userActiveChats = await activeChatsCollection
      .find({ userIds: userId })
      .toArray();
    const activePrivateChats = [];
    for (const chat of userActiveChats) {
      const partnerUserId = chat.userIds.find((id) => id !== userId);
      // Find partner in currently online users first
      const partnerSocketId = Object.keys(users).find(
        (key) => users[key].userId === partnerUserId
      );
      let partnerInfo;
      if (partnerSocketId) {
        partnerInfo = users[partnerSocketId];
      } else {
        // If not online, fetch from DB
        try {
          const partnerDbInfo = await usersCollection.findOne({
            _id: new ObjectId(partnerUserId),
          });
          if (partnerDbInfo) {
            partnerInfo = {
              id: null,
              userId: partnerUserId,
              name: partnerDbInfo.username,
              profilePicture: partnerDbInfo.profilePicture,
            };
          }
        } catch (e) {
          console.error("Error fetching offline partner info:", e);
        }
      }
      if (partnerInfo) {
        activePrivateChats.push({ room: chat.roomId, withUser: partnerInfo });
      }
    }

    // Send session details with fresh profile data
    socket.emit("session details", {
      socketId: socket.id,
      userId: userId,
      activePrivateChats,
      groups: userGroups,
      userProfile: {
        name: users[socket.id].name,
        profilePicture: users[socket.id].profilePicture,
      },
      initialRoom: {
        id: "public",
        name: "🌐 Public Chat",
        type: "public",
        history: roomMessageCache["public"] || [],
      },
    });

    io.emit("user list", Object.values(users));
    socket.emit("game:roomsList", getPublicRoomList());

    socket.on("join room", async (roomId) => {
      // Leave previous public/game rooms, but not private/group chats
      socket.rooms.forEach((room) => {
        if (
          room !== socket.id &&
          !room.startsWith("group-") &&
          !room.includes(userId)
        ) {
          socket.leave(room);
        }
      });
      socket.join(roomId);

      if (roomMessageCache[roomId]) {
        socket.emit("room history", roomMessageCache[roomId]);
      } else {
        try {
          const history = await messagesCollection
            .find({ room: roomId })
            .sort({ timestamp: -1 })
            .limit(50)
            .toArray();
          const reversedHistory = history.reverse();
          roomMessageCache[roomId] = reversedHistory;
          socket.emit("room history", reversedHistory);
        } catch (err) {
          console.error(`Error fetching history for room ${roomId}:`, err);
        }
      }
    });

    socket.on("chat message", async ({ room, text }) => {
      const user = users[socket.id];
      if (!user) return;
      if (
        typeof text !== "string" ||
        text.trim().length === 0 ||
        text.length > 500
      )
        return;

      const now = Date.now();
      userMessageTimestamps[socket.id] = (
        userMessageTimestamps[socket.id] || []
      ).filter((ts) => now - ts < RATE_LIMIT_SECONDS * 1000);
      if (userMessageTimestamps[socket.id].length >= RATE_LIMIT_COUNT) {
        socket.emit("rate limit", "You are sending messages too quickly.");
        return;
      }
      userMessageTimestamps[socket.id].push(now);

      const gameState = gameStates[room];
      const roomData = activeGameRooms[room];
      if (
        gameState &&
        gameState.isRoundActive &&
        roomData &&
        roomData.gameType === "doodle"
      ) {
        handleDoodleGuess(socket, user, room, text, gameState);
        return;
      }

      if (room.startsWith("group-")) {
        const groupId = room.split("-")[1];
        const group = await groupsCollection.findOne({
          _id: new ObjectId(groupId),
          members: user.userId,
        });
        if (!group) {
          return socket.emit("error", "You are not a member of this group.");
        }
      }

      const messageId = `${Date.now()}-${socket.id}`;
      const msg = {
        id: socket.id,
        userId: user.userId,
        messageId,
        name: user.name,
        profilePicture: user.profilePicture,
        text: text.trim(),
        room,
        status: "sent",
        timestamp: new Date(),
      };

      try {
        await messagesCollection.insertOne(msg);
        if (!roomMessageCache[room]) {
          roomMessageCache[room] = [];
        }
        roomMessageCache[room].push(msg);
        if (roomMessageCache[room].length > 50) {
          roomMessageCache[room].shift();
        }
        io.to(room).emit("chat message", msg);
      } catch (err) {
        console.error("Error saving message:", err);
      }
    });

    // Audio Message Handler
    socket.on("audio message", async ({ room, audioData }) => {
      const user = users[socket.id];
      if (!user) return;

      const messageId = `${Date.now()}-${socket.id}`;
      const msg = {
        id: socket.id,
        userId: user.userId,
        messageId,
        name: user.name,
        profilePicture: user.profilePicture,
        audioData: audioData,
        room,
        status: "sent",
        timestamp: new Date(),
      };

      try {
        await messagesCollection.insertOne(msg);
        if (!roomMessageCache[room]) {
          roomMessageCache[room] = [];
        }
        roomMessageCache[room].push(msg);
        if (roomMessageCache[room].length > 50) {
          roomMessageCache[room].shift();
        }
        io.to(room).emit("chat message", msg);
      } catch (err) {
        console.error("Error saving audio message:", err);
      }
    });

    socket.on("share file", async ({ room, file, fileName, fileType }) => {
      const user = users[socket.id];
      if (!user) return;
      const messageId = `${Date.now()}-${socket.id}`;
      const msg = {
        id: socket.id,
        userId: user.userId,
        messageId,
        name: user.name,
        profilePicture: user.profilePicture,
        file,
        fileName,
        fileType,
        room,
        status: "sent",
        timestamp: new Date(),
      };
      try {
        await messagesCollection.insertOne(msg);
        if (!roomMessageCache[room]) {
          roomMessageCache[room] = [];
        }
        roomMessageCache[room].push(msg);
        if (roomMessageCache[room].length > 50) {
          roomMessageCache[room].shift();
        }
        io.to(room).emit("chat message", msg);
      } catch (err) {
        console.error("Error saving file message:", err);
      }
    });

    socket.on("message read", ({ room, messageId }) => {
      const messageParts = messageId.split("-");
      if (messageParts.length < 2) return;
      const senderSocketId = messageParts[messageParts.length - 1];
      if (senderSocketId) {
        io.to(senderSocketId).emit("message was read", { room, messageId });
      }
    });

    socket.on("typing", ({ room }) => {
      const user = users[socket.id];
      if (user) socket.to(room).emit("typing", { name: user.name, room });
    });

    socket.on("stop typing", ({ room }) => {
      const user = users[socket.id];
      if (user) socket.to(room).emit("stop typing", { name: user.name, room });
    });

    socket.on("private:initiate", async ({ targetId }) => {
      const requester = users[socket.id];
      const target = users[targetId];
      if (!requester || !target) {
        return socket.emit("private:request_error", "User not found.");
      }
      const privateRoomId = [requester.userId, target.userId].sort().join("-");
      const existingChat = await activeChatsCollection.findOne({
        roomId: privateRoomId,
      });
      if (existingChat) {
        const roomInfo = { id: privateRoomId, name: `Private Chat` };
        io.to(socket.id).emit("private:request_accepted", {
          room: roomInfo,
          withUser: target,
        });
        return;
      }
      const declineKey = `${targetId}-${socket.id}`;
      if (declinedChats.has(declineKey)) {
        return socket.emit(
          "private:request_error",
          `${target.name} has declined your recent request.`
        );
      }
      if (
        pendingPrivateRequests[socket.id] ||
        Object.values(pendingPrivateRequests).includes(socket.id)
      ) {
        return socket.emit(
          "private:request_error",
          "You already have a pending request."
        );
      }
      pendingPrivateRequests[socket.id] = targetId;
      io.to(targetId).emit("private:request_incoming", { fromUser: requester });
    });

    socket.on("private:accept", async ({ requesterId }) => {
      const accepter = users[socket.id];
      const requester = users[requesterId];
      if (
        !accepter ||
        !requester ||
        pendingPrivateRequests[requesterId] !== socket.id
      ) {
        return;
      }
      delete pendingPrivateRequests[requesterId];
      const privateRoomId = [requester.userId, accepter.userId]
        .sort()
        .join("-");
      await activeChatsCollection.updateOne(
        { roomId: privateRoomId },
        {
          $setOnInsert: {
            roomId: privateRoomId,
            userIds: [requester.userId, accepter.userId],
          },
        },
        { upsert: true }
      );
      const declineKey1 = `${socket.id}-${requesterId}`;
      const declineKey2 = `${requesterId}-${socket.id}`;
      declinedChats.delete(declineKey1);
      declinedChats.delete(declineKey2);
      const roomInfo = { id: privateRoomId, name: `Private Chat` };
      io.to(requesterId).emit("private:request_accepted", {
        room: roomInfo,
        withUser: accepter,
      });
      io.to(socket.id).emit("private:request_accepted", {
        room: roomInfo,
        withUser: requester,
      });
    });

    socket.on("private:decline", ({ requesterId, reason }) => {
      const decliner = users[socket.id];
      if (!decliner || !users[requesterId]) return;
      if (pendingPrivateRequests[requesterId] === socket.id) {
        delete pendingPrivateRequests[requesterId];
      }
      const declineKey = `${socket.id}-${requesterId}`;
      declinedChats.add(declineKey);
      io.to(requesterId).emit("private:request_declined", {
        byUser: decliner,
        reason,
      });
    });

    socket.on("private:leave", async ({ room }) => {
      const user = users[socket.id];
      if (user) {
        socket
          .to(room)
          .emit("private:partner_left", { room, partnerName: user.name });
      }
      socket.leave(room);
      await activeChatsCollection.deleteOne({ roomId: room });
    });

    function resetCallState(socketId) {
      if (callStates[socketId]) {
        callStates[socketId].status = "idle";
        callStates[socketId].partnerId = null;
      }
    }

    socket.on("call:offer", ({ targetId, offer }) => {
      const caller = users[socket.id];
      const target = users[targetId];
      if (!caller || !target) return;
      if (callStates[socket.id]?.status !== "idle") {
        return socket.emit("call:error", "You are already in a call process.");
      }
      if (callStates[targetId]?.status !== "idle") {
        return socket.emit("call:busy", {
          from: { id: targetId, name: target.name },
        });
      }
      callStates[socket.id] = { status: "offering", partnerId: targetId };
      callStates[targetId] = { status: "receiving", partnerId: socket.id };
      io.to(targetId).emit("call:incoming", { from: { ...caller }, offer });
    });

    socket.on("call:answer", ({ targetId, answer }) => {
      const callee = users[socket.id];
      if (!callee || callStates[socket.id]?.partnerId !== targetId) return;
      callStates[socket.id].status = "connected";
      if (callStates[targetId]) {
        callStates[targetId].status = "connected";
      }
      io.to(targetId).emit("call:answer_received", { from: socket.id, answer });
    });

    socket.on("call:ice_candidate", ({ targetId, candidate }) => {
      if (callStates[socket.id]?.partnerId === targetId) {
        io.to(targetId).emit("call:ice_candidate_received", {
          fromId: socket.id,
          candidate,
        });
      }
    });

    socket.on("call:decline", ({ targetId, reason }) => {
      const decliner = users[socket.id];
      if (!decliner) return;
      io.to(targetId).emit("call:declined", {
        from: { id: socket.id, name: decliner.name },
        reason,
      });
      resetCallState(socket.id);
      resetCallState(targetId);
    });

    const endCallCleanup = (enderId) => {
      const callState = callStates[enderId];
      if (!callState || callState.status === "idle") return;
      const partnerId = callState.partnerId;
      if (partnerId && users[partnerId]) {
        io.to(partnerId).emit("call:ended", { fromId: enderId });
      }
      resetCallState(enderId);
      if (partnerId) {
        resetCallState(partnerId);
      }
    };
    socket.on("call:end", () => endCallCleanup(socket.id));

    // Group Handlers
    socket.on("group:create", async ({ name, memberIds }) => {
      const creatorId = users[socket.id].userId;
      const allMemberIds = [...new Set([creatorId, ...memberIds])]; // Include creator, ensure unique

      if (allMemberIds.length > 10) {
        return socket.emit(
          "group:create_error",
          "Groups cannot have more than 10 members."
        );
      }

      const newGroup = {
        name,
        creator: creatorId,
        members: allMemberIds,
        createdAt: new Date(),
      };

      const result = await groupsCollection.insertOne(newGroup);
      const createdGroup = await groupsCollection.findOne({
        _id: result.insertedId,
      });

      // Notify all members
      allMemberIds.forEach((memberId) => {
        const memberSocketId = userIdToSocketId[memberId];
        if (memberSocketId) {
          io.to(memberSocketId).emit(
            memberId === creatorId ? "group:created" : "group:invited",
            createdGroup
          );
        }
      });
    });

    socket.on("group:add_member", async ({ groupId, userIdToAdd }) => {
      const requesterId = users[socket.id].userId;
      const group = await groupsCollection.findOne({
        _id: new ObjectId(groupId),
      });

      if (group && group.members.length >= 10) {
        return socket.emit(
          "group:update_error",
          "Group is full (10 members max)."
        );
      }

      if (group && group.creator.toString() === requesterId) {
        await groupsCollection.updateOne(
          { _id: new ObjectId(groupId) },
          { $addToSet: { members: userIdToAdd } }
        );
        const updatedGroup = await groupsCollection.findOne({
          _id: new ObjectId(groupId),
        });

        const newMemberSocketId = userIdToSocketId[userIdToAdd];
        if (newMemberSocketId) {
          const newMemberSocket = io.sockets.sockets.get(newMemberSocketId);
          if (newMemberSocket) {
            newMemberSocket.join(`group-${groupId}`);
          }
          io.to(newMemberSocketId).emit("group:invited", updatedGroup);
        }

        io.to(`group-${groupId}`).emit("group:updated", updatedGroup);
      }
    });

    socket.on("group:remove_member", async ({ groupId, userIdToRemove }) => {
      const requesterId = users[socket.id].userId;
      const group = await groupsCollection.findOne({
        _id: new ObjectId(groupId),
      });

      if (
        group &&
        group.creator.toString() === requesterId &&
        requesterId !== userIdToRemove
      ) {
        await groupsCollection.updateOne(
          { _id: new ObjectId(groupId) },
          { $pull: { members: userIdToRemove } }
        );
        const updatedGroup = await groupsCollection.findOne({
          _id: new ObjectId(groupId),
        });

        const removedMemberSocketId = userIdToSocketId[userIdToRemove];
        if (removedMemberSocketId) {
          const removedMemberSocket = io.sockets.sockets.get(
            removedMemberSocketId
          );
          io.to(removedMemberSocketId).emit("group:removed", {
            groupId,
            groupName: group.name,
          });
          if (removedMemberSocket) {
            removedMemberSocket.leave(`group-${groupId}`);
          }
        }

        io.to(`group-${groupId}`).emit("group:updated", updatedGroup);
      }
    });

    socket.on("group:delete", async ({ groupId }) => {
      const requesterId = users[socket.id].userId;
      const group = await groupsCollection.findOne({
        _id: new ObjectId(groupId),
      });

      if (group && group.creator.toString() === requesterId) {
        io.to(`group-${groupId}`).emit("group:deleted", {
          groupId,
          groupName: group.name,
        });

        const socketsInRoom = io.sockets.adapter.rooms.get(`group-${groupId}`);
        if (socketsInRoom) {
          socketsInRoom.forEach((socketId) => {
            const socketInstance = io.sockets.sockets.get(socketId);
            if (socketInstance) socketInstance.leave(`group-${groupId}`);
          });
        }

        await groupsCollection.deleteOne({ _id: new ObjectId(groupId) });
        await messagesCollection.deleteMany({ room: `group-${groupId}` });
      }
    });

    // --- NEW: PEER-TO-PEER FILE TRANSFER SIGNALING ---
    socket.on("file:request", ({ targetId, file }) => {
      const requester = users[socket.id];
      const targetSocket = io.sockets.sockets.get(targetId);
      if (requester && targetSocket) {
        io.to(targetId).emit("file:request_incoming", {
          fromUser: requester,
          file,
        });
      }
    });

    socket.on("file:accept", ({ targetId }) => {
      const targetSocket = io.sockets.sockets.get(targetId);
      if (targetSocket) {
        io.to(targetId).emit("file:request_accepted", {
          byUser: users[socket.id],
        });
      }
    });

    socket.on("file:decline", ({ targetId, reason }) => {
      const targetSocket = io.sockets.sockets.get(targetId);
      if (targetSocket) {
        io.to(targetId).emit("file:request_declined", {
          byUser: users[socket.id],
          reason,
        });
      }
    });

    socket.on("file:signal", ({ targetId, senderId, signal }) => {
      io.to(targetId).emit("file:signal", { senderId, signal });
    });

    // --- NEW & IMPROVED: GROUP CALL SIGNALING ---
    socket.on("group-call:start", async ({ groupId, callType }) => {
      const caller = users[socket.id];
      if (!caller) return;

      try {
        // Fetch the group details from the database
        const group = await groupsCollection.findOne({
          _id: new ObjectId(groupId),
        });
        if (!group) {
          console.error(
            `Attempted to start call in non-existent group: ${groupId}`
          );
          return;
        }

        // Notify all other members in the group's socket.io room
        io.to(`group-${groupId}`)
          .except(socket.id)
          .emit("group-call:incoming", {
            group: { id: groupId, name: group.name },
            caller: caller,
            callType: callType,
          });
      } catch (error) {
        console.error("Error starting group call:", error);
      }
    });

    socket.on("group-call:join", ({ roomId }) => {
      socket.join(roomId);

      if (!activeGroupCalls[roomId]) {
        activeGroupCalls[roomId] = new Set();
      }

      const otherParticipants = Array.from(activeGroupCalls[roomId]);
      const participantDetails = otherParticipants
        .map((id) => users[id])
        .filter(Boolean);

      socket.emit("group-call:all-participants", participantDetails);
      activeGroupCalls[roomId].add(socket.id);

      socket.to(roomId).emit("group-call:new-participant", users[socket.id]);
    });

    socket.on("group-call:signal", ({ targetId, senderId, signal }) => {
      // Relay signal to the specific target user in the group call
      io.to(targetId).emit("group-call:signal", { senderId, signal });
    });

    socket.on("group-call:leave", ({ roomId }) => {
      if (activeGroupCalls[roomId]) {
        activeGroupCalls[roomId].delete(socket.id);
        socket.to(roomId).emit("group-call:participant-left", {
          socketId: socket.id,
          name: users[socket.id]?.name,
        });
        if (activeGroupCalls[roomId].size === 0) {
          delete activeGroupCalls[roomId];
        }
      }
      socket.leave(roomId);
    });

    // Disconnect Handler
    socket.on("disconnect", async () => {
      console.log("🔴 User disconnected:", socket.id);
      endCallCleanup(socket.id);
      const user = users[socket.id];
      if (user) {
        // Handle group call disconnect
        for (const roomId in activeGroupCalls) {
          if (
            activeGroupCalls[roomId] &&
            activeGroupCalls[roomId].has(socket.id)
          ) {
            activeGroupCalls[roomId].delete(socket.id);
            socket.to(roomId).emit("group-call:participant-left", {
              socketId: socket.id,
              name: user.name,
            });
            if (activeGroupCalls[roomId].size === 0) {
              delete activeGroupCalls[roomId];
            }
          }
        }

        if (userIdToSocketId[user.userId] === socket.id) {
          delete userIdToSocketId[user.userId];
        }
        const userActiveChats = await activeChatsCollection
          .find({ userIds: user.userId })
          .toArray();
        for (const chat of userActiveChats) {
          const partnerUserId = chat.userIds.find((id) => id !== user.userId);
          const partnerSocketId = Object.keys(users).find(
            (key) => users[key].userId === partnerUserId
          );
          if (partnerSocketId) {
            io.to(partnerSocketId).emit("private:partner_left", {
              room: chat.roomId,
              partnerName: user.name,
            });
          }
        }
        for (const roomId in activeGameRooms) {
          // FIX: Only remove player from games they are actually in
          if (activeGameRooms[roomId].players.some((p) => p.id === socket.id)) {
            handlePlayerLeave(socket.id, roomId);
          }
        }
      }
      if (pendingPrivateRequests[socket.id]) {
        delete pendingPrivateRequests[socket.id];
      }
      for (const requesterId in pendingPrivateRequests) {
        if (pendingPrivateRequests[requesterId] === socket.id) {
          io.to(requesterId).emit("private:request_declined", {
            byUser: { name: user ? user.name : "A user" },
            reason: "offline",
          });
          delete pendingPrivateRequests[requesterId];
        }
      }
      const declinedPairsToRemove = [];
      for (const pair of declinedChats) {
        if (pair.includes(socket.id)) declinedPairsToRemove.push(pair);
      }
      declinedPairsToRemove.forEach((pair) => declinedChats.delete(pair));
      delete users[socket.id];
      delete userMessageTimestamps[socket.id];
      delete callStates[socket.id];
      io.emit("user list", Object.values(users));
    });

    // --- Game related handlers ---
    socket.on("game:create", ({ roomName, password, gameType }) => {
      const user = users[socket.id];
      if (!user) return;
      const roomId = `game-${randomUUID()}`;
      const newRoom = {
        id: roomId,
        name: roomName || `${user.name}'s Room`,
        creatorId: socket.id,
        creatorName: user.name,
        players: [user],
        password: password || null,
        inProgress: false,
        gameType: gameType || "doodle",
      };
      activeGameRooms[roomId] = newRoom;
      socket.join(roomId);
      socket.emit("game:joined", newRoom);
      io.emit("game:roomsList", getPublicRoomList());
      io.to(roomId).emit("game:state", {
        gameType: newRoom.gameType,
        players: newRoom.players,
        creatorId: newRoom.creatorId,
        isRoundActive: false,
        scores: {},
      });
    });
    socket.on("game:join", ({ roomId, password }) => {
      const user = users[socket.id];
      const room = activeGameRooms[roomId];
      if (!user || !room) return;
      if (room.inProgress) {
        socket.emit("game:join_error", "This game is already in progress.");
        return;
      }
      if (room.password && room.password !== password) {
        socket.emit("game:join_error", "Incorrect password.");
        return;
      }
      if (room.players.some((p) => p.id === user.id)) return;
      if (room.gameType === "hangman" && room.players.length >= 2) {
        socket.emit(
          "game:join_error",
          "This Hangman room is full (2 players max)."
        );
        return;
      }
      room.players.push(user);
      socket.join(roomId);
      socket.emit("game:joined", room);
      io.to(roomId).emit("chat message", {
        room: roomId,
        text: `${user.name} has joined the game!`,
        name: "System",
      });
      const gameState = gameStates[roomId] || {};
      io.to(roomId).emit("game:state", {
        ...gameState,
        gameType: room.gameType,
        players: room.players,
        creatorId: room.creatorId,
        isRoundActive: gameState.isRoundActive || false,
      });
      if (gameState.isRoundActive && gameState.drawingHistory) {
        socket.emit("game:drawing_history", gameState.drawingHistory);
      }
      io.emit("game:roomsList", getPublicRoomList());
    });
    socket.on("game:leave", (roomId) => {
      socket.leave(roomId);
      handlePlayerLeave(socket.id, roomId);
    });
    socket.on("game:start", (roomId) => {
      const room = activeGameRooms[roomId];
      const user = users[socket.id];
      if (!room || !user || user.id !== room.creatorId) return;
      if (room.gameType === "hangman" && room.players.length !== 2) {
        socket.emit(
          "game:message",
          `Hangman requires exactly 2 players to start.`
        );
        return;
      }
      if (room.gameType === "doodle" && room.players.length < 2) {
        socket.emit(
          "game:message",
          `Doodle Dash requires at least 2 players to start.`
        );
        return;
      }
      room.inProgress = true;
      if (room.gameType === "doodle") {
        const initialScores = {};
        room.players.forEach((p) => (initialScores[p.id] = 0));
        gameStates[roomId] = {
          gameType: "doodle",
          players: room.players.map((p) => p.id),
          scores: initialScores,
          isRoundActive: false,
          creatorId: room.creatorId,
          currentPlayerIndex: -1,
          drawingHistory: [],
          usedWords: new Set(),
        };
        startNewDoodleRound(roomId);
      } else if (room.gameType === "hangman") {
        gameStates[roomId] = {
          gameType: "hangman",
          players: room.players.map((p) => p.id),
          isRoundActive: false,
          creatorId: room.creatorId,
        };
        startNewHangmanRound(roomId);
      }
      io.emit("game:roomsList", getPublicRoomList());
    });
    socket.on("game:stop", (roomId) => {
      const room = activeGameRooms[roomId];
      const user = users[socket.id];
      if (!room || !user || user.id !== room.creatorId) return;
      io.to(roomId).emit(
        "game:terminated",
        "The host has terminated the game."
      );
      const socketsInRoom = io.sockets.adapter.rooms.get(roomId);
      if (socketsInRoom) {
        socketsInRoom.forEach((socketId) =>
          io.sockets.sockets.get(socketId).leave(roomId)
        );
      }
      delete activeGameRooms[roomId];
      delete gameStates[roomId];
      io.emit("game:roomsList", getPublicRoomList());
    });

    socket.on("game:word_selected", ({ word, room }) => {
      const gameState = gameStates[room];
      if (gameState && gameState.drawer.id === socket.id && !gameState.word) {
        gameState.word = word;
        gameState.isRoundActive = true;
        const roundEndTime = Date.now() + DOODLE_ROUND_TIME;
        gameState.roundEndTime = roundEndTime;

        io.to(room).emit("game:new_round"); // Tell others the round is starting

        if (gameState.roundTimer) clearTimeout(gameState.roundTimer);
        gameState.roundTimer = setTimeout(() => {
          io.to(room).emit(
            "game:message",
            `Time's up! The word was '${word}'.`
          );
          setTimeout(() => startNewDoodleRound(room), 3000);
        }, DOODLE_ROUND_TIME);

        io.to(room).emit("game:state", {
          // ... send full state
          gameType: "doodle",
          drawer: gameState.drawer,
          isRoundActive: true,
          scores: gameState.scores,
          creatorId: activeGameRooms[room].creatorId,
          players: activeGameRooms[room].players,
          roundEndTime: roundEndTime,
        });
      }
    });

    socket.on("game:draw", ({ room, data }) => {
      const gameState = gameStates[room];
      if (
        gameState &&
        gameState.isRoundActive &&
        socket.id === gameState.drawer.id
      ) {
        gameState.drawingHistory.push(data);
        socket.to(room).emit("game:draw", data);
      }
    });

    socket.on("game:clear_canvas", (room) => {
      const gameState = gameStates[room];
      if (gameState && gameState.drawer.id === socket.id) {
        gameState.drawingHistory = [];
        io.to(room).emit("game:clear_canvas");
      }
    });
    socket.on("hangman:guess", ({ room, letter }) => {
      const user = users[socket.id];
      const gameState = gameStates[room];
      if (
        !user ||
        !gameState ||
        !gameState.isRoundActive ||
        gameState.gameType !== "hangman"
      )
        return;
      if (socket.id !== gameState.currentPlayerTurn) {
        socket.emit("rate limit", "It's not your turn to guess.");
        return;
      }
      handleHangmanGuess(socket, user, room, letter, gameState);
    });
  });

  // --- Game Logic Functions ---
  function handleDoodleGuess(socket, user, room, text, gameState) {
    if (socket.id === gameState.drawer.id) {
      socket.emit("rate limit", "You cannot chat while drawing.");
      return;
    }
    if (text.trim().toLowerCase() === gameState.word.toLowerCase()) {
      clearTimeout(gameState.roundTimer);
      const drawerSocketId = gameState.drawer.id;
      gameState.scores[socket.id] = (gameState.scores[socket.id] || 0) + 2;
      if (users[drawerSocketId]) {
        gameState.scores[drawerSocketId] =
          (gameState.scores[drawerSocketId] || 0) + 1;
      }
      io.to(room).emit("game:correct_guess", {
        guesser: user,
        word: gameState.word,
      });
      const winnerId = Object.keys(gameState.scores).find(
        (id) => gameState.scores[id] >= WINNING_SCORE
      );
      if (winnerId && users[winnerId]) {
        io.to(room).emit("game:over", {
          winner: users[winnerId],
          scores: { ...gameState.scores },
        });
        delete activeGameRooms[room];
        delete gameStates[room];
        io.emit("game:roomsList", getPublicRoomList());
      } else {
        setTimeout(() => startNewDoodleRound(room), 3000);
      }
    } else {
      const msg = {
        id: user.id,
        userId: user.userId,
        name: user.name,
        profilePicture: user.profilePicture,
        text,
        room,
      };
      io.to(room).emit("chat message", msg);
    }
  }

  function startNewDoodleRound(roomId) {
    const gameState = gameStates[roomId];
    const room = activeGameRooms[roomId];
    if (!gameState || !room || room.players.length < 2) {
      if (room) room.inProgress = false;
      if (gameState) gameState.isRoundActive = false;
      io.to(roomId).emit("game:end", "Not enough players. Waiting for more...");
      io.to(roomId).emit("game:state", {
        gameType: "doodle",
        creatorId: room ? room.creatorId : null,
        players: room ? room.players : [],
        isRoundActive: false,
        scores: gameState ? gameState.scores : {},
      });
      io.emit("game:roomsList", getPublicRoomList());
      return;
    }
    gameState.drawingHistory = [];
    gameState.players = room.players.map((p) => p.id);
    const nextDrawerIndex =
      (gameState.currentPlayerIndex + 1) % gameState.players.length;
    gameState.currentPlayerIndex = nextDrawerIndex;
    const drawerId = gameState.players[nextDrawerIndex];
    const drawerUser = users[drawerId];
    if (!drawerUser) {
      console.log(`Could not find drawer user for id ${drawerId}, skipping.`);
      startNewDoodleRound(roomId);
      return;
    }

    // Select 3 words
    let availableWords = DOODLE_WORDS.filter(
      (w) => !gameState.usedWords.has(w)
    );
    if (availableWords.length < 3) {
      gameState.usedWords.clear();
      availableWords = DOODLE_WORDS;
    }
    const wordOptions = [];
    for (let i = 0; i < 3; i++) {
      const randomIndex = Math.floor(Math.random() * availableWords.length);
      wordOptions.push(availableWords.splice(randomIndex, 1)[0]);
    }

    gameState.drawer = drawerUser;
    gameState.word = null; // Word is not set until drawer chooses
    gameState.isRoundActive = false;

    // Send words ONLY to the drawer
    io.to(drawerId).emit("game:present_words", wordOptions);

    // Notify everyone else to wait
    io.to(roomId).emit("game:state", {
      gameType: "doodle",
      drawer: drawerUser,
      isRoundActive: false, // Waiting for word selection
      scores: gameState.scores,
      creatorId: room.creatorId,
      players: room.players,
    });
  }

  function getSerializableGameState(gameState) {
    const stateToSend = { ...gameState };
    delete stateToSend.turnTimer;
    return stateToSend;
  }

  function startNewHangmanRound(roomId) {
    const room = activeGameRooms[roomId];
    const gameState = gameStates[roomId];
    if (!room || !gameState || room.players.length < 2) {
      if (room) room.inProgress = false;
      io.to(roomId).emit("game:end", "Not enough players. Game over.");
      io.emit("game:roomsList", getPublicRoomList());
      return;
    }
    const word =
      HANGMAN_WORDS[Math.floor(Math.random() * HANGMAN_WORDS.length)];
    const lastWinnerIndex = gameState.lastWinnerIndex;
    let currentPlayerIndex =
      typeof lastWinnerIndex === "number"
        ? (lastWinnerIndex + 1) % 2
        : Math.floor(Math.random() * 2);
    Object.assign(gameState, {
      word: word.toLowerCase(),
      displayWord: Array(word.length)
        .fill("_")
        .map((c, i) => (word[i] === " " ? " " : "_")),
      incorrectGuesses: [],
      correctGuesses: word.includes(" ") ? [" "] : [],
      isRoundActive: true,
      isGameOver: false,
      winner: null,
      currentPlayerIndex: currentPlayerIndex,
      currentPlayerTurn: room.players[currentPlayerIndex].id,
    });
    io.to(roomId).emit("game:new_round");
    setHangmanTurnTimer(roomId);
    io.to(roomId).emit("game:state", {
      gameType: "hangman",
      ...getSerializableGameState(gameState),
      players: room.players,
      creatorId: room.creatorId,
    });
  }

  function handleHangmanGuess(socket, user, room, letter, gameState) {
    if (gameState.turnTimer) clearTimeout(gameState.turnTimer);
    const cleanedLetter = letter.trim().toLowerCase();
    if (cleanedLetter.length !== 1 || !/^[a-z]$/.test(cleanedLetter)) {
      socket.emit("rate limit", "Please guess a single letter.");
      setHangmanTurnTimer(room);
      return;
    }
    if (
      gameState.correctGuesses.includes(cleanedLetter) ||
      gameState.incorrectGuesses.includes(cleanedLetter)
    ) {
      socket.emit("rate limit", `You already guessed '${cleanedLetter}'.`);
      setHangmanTurnTimer(room);
      return;
    }
    const word = gameState.word;
    let isCorrect = false;
    if (word.includes(cleanedLetter)) {
      isCorrect = true;
      gameState.correctGuesses.push(cleanedLetter);
      gameState.displayWord = word
        .split("")
        .map((char) => (gameState.correctGuesses.includes(char) ? char : "_"));
      io.to(room).emit("chat message", {
        room,
        text: `${
          user.name
        } guessed a correct letter: ${cleanedLetter.toUpperCase()}`,
        name: "System",
      });
    } else {
      gameState.incorrectGuesses.push(cleanedLetter);
      io.to(room).emit("chat message", {
        room,
        text: `${
          user.name
        } guessed an incorrect letter: ${cleanedLetter.toUpperCase()}`,
        name: "System",
      });
    }
    const won = !gameState.displayWord.includes("_");
    const lost = gameState.incorrectGuesses.length >= MAX_INCORRECT_GUESSES;
    if (won || lost) {
      gameState.isRoundActive = false;
      gameState.isGameOver = true;
      gameState.winner = won ? user : null;
      gameState.lastWinnerIndex = won
        ? gameState.currentPlayerIndex
        : (gameState.currentPlayerIndex + 1) % 2;
      const message = won
        ? `🎉 ${user.name} won! The word was "${word}".`
        : `😥 Game over! The word was "${word}".`;
      io.to(room).emit("game:message", message);
      setTimeout(() => startNewHangmanRound(room), 5000);
    } else {
      if (!isCorrect) {
        const currentRoom = activeGameRooms[room];
        gameState.currentPlayerIndex =
          (gameState.currentPlayerIndex + 1) % currentRoom.players.length;
        gameState.currentPlayerTurn =
          currentRoom.players[gameState.currentPlayerIndex].id;
      }
      setHangmanTurnTimer(room);
    }
    io.to(room).emit("game:state", {
      gameType: "hangman",
      ...getSerializableGameState(gameState),
    });
  }

  function setHangmanTurnTimer(roomId) {
    const gameState = gameStates[roomId];
    if (!gameState || !gameState.isRoundActive) return;
    if (gameState.turnTimer) clearTimeout(gameState.turnTimer);
    gameState.turnEndTime = Date.now() + HANGMAN_TURN_TIME;
    gameState.turnTimer = setTimeout(
      () => handleHangmanTimeout(roomId),
      HANGMAN_TURN_TIME
    );
    io.to(roomId).emit("game:state", {
      gameType: "hangman",
      ...getSerializableGameState(gameState),
    });
  }

  function handleHangmanTimeout(roomId) {
    const gameState = gameStates[roomId];
    if (!gameState || !gameState.isRoundActive) return;
    const timedOutPlayer = users[gameState.currentPlayerTurn];
    io.to(roomId).emit("chat message", {
      room: roomId,
      text: `${
        timedOutPlayer ? timedOutPlayer.name : "Player"
      }'s turn timed out.`,
      name: "System",
    });
    gameState.incorrectGuesses.push(" ");
    const lost = gameState.incorrectGuesses.length >= MAX_INCORRECT_GUESSES;
    if (lost) {
      gameState.isRoundActive = false;
      gameState.isGameOver = true;
      io.to(roomId).emit(
        "game:message",
        `😥 Game over! The word was "${gameState.word}".`
      );
      gameState.lastWinnerIndex = (gameState.currentPlayerIndex + 1) % 2;
      setTimeout(() => startNewHangmanRound(roomId), 5000);
    } else {
      const currentRoom = activeGameRooms[roomId];
      gameState.currentPlayerIndex =
        (gameState.currentPlayerIndex + 1) % currentRoom.players.length;
      gameState.currentPlayerTurn =
        currentRoom.players[gameState.currentPlayerIndex].id;
      setHangmanTurnTimer(roomId);
    }
    io.to(roomId).emit("game:state", {
      gameType: "hangman",
      ...getSerializableGameState(gameState),
    });
  }

  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
  });
}

startServer();
