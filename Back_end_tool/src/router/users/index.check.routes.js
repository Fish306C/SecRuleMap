const router = require("./user.check.routes");
const middleware = require("./../../middleware/client/checkaccount");
module.exports = (app) => {
  app.use("/user/check", middleware.checkaccount, router);
};
