const { MongoClient, ServerApiVersion } = require("mongodb");
const mongoUri = process.env.MONGO_URI;
const client = new MongoClient(mongoUri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;

async function connectToDb() {
  if (db) return db;
  try {
    await client.connect();
    db = client.db("chat_app");
    console.log("✅ Successfully connected to MongoDB!");
    return db;
  } catch (err) {
    console.error("🔴 Failed to connect to MongoDB", err);
    process.exit(1);
  }
}

module.exports = { connectToDb };
