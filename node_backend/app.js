require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Sequelize } = require("sequelize");
const { router } = require("./apidiscovery");

const app = express();
app.use(cors());
app.use(express.json());

const sequelizeDb = new Sequelize(
  process.env.DB_NAME || "ApiDiscoveryDb",
  process.env.DB_USER || "root",
  process.env.DB_PASSWORD || "",
  {
    host: process.env.DB_HOST || "localhost",
    port: process.env.DB_PORT || 3306,
    dialect: "mysql",
    logging: false,
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000,
    },
  }
);

sequelizeDb
  .authenticate()
  .then(() => console.log("DB connected successfully."))
  .catch((err) => console.error("DB connection failed:", err.message));

app.use((req, res, next) => {
  req.db = sequelizeDb;
  next();
});

app.use("/api", router);

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
    payload: [],
    payloadCount: 0,
    totalCount: 0,
  });
});

const PORT = process.env.NODE_PORT || 3001;
app.listen(PORT, () => {
  console.log(`Node API running on http://0.0.0.0:${PORT}`);
});