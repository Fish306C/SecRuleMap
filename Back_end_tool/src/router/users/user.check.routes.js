const express = require("express");
const routerUserCheck = express.Router();
const userController = require("../../controller/Users/user.controller");
routerUserCheck.get("/profile", userController.getProfile);
// routerUserCheck.post("/scan/project", userController.postScan);
routerUserCheck.post("/start", userController.startScan);

module.exports = routerUserCheck;
