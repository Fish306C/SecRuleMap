const router = require("./user.notcheck.routes");
module.exports = (app) => {
  app.use("/api/compliance", router);
};
