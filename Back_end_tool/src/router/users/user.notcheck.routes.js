const express = require("express");
const routerUserNotCheck = express.Router();
const Usercontroller = require("./../../controller/Users/user.controller");
routerUserNotCheck.post("/loginUser", Usercontroller.login);
routerUserNotCheck.post("/register", Usercontroller.register);
routerUserNotCheck.post("/webscan", Usercontroller.getWebScan);
module.exports = routerUserNotCheck;
