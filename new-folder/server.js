const express = require("express");
const cors = require("cors");
const alertRoutes = require("./routes/alerts");

const app = express();
app.use(cors());
app.use(express.json());

app.use("/api/alerts", alertRoutes);

app.listen(5000, () => {
  console.log("SOAR backend running on http://localhost:5000");
});
