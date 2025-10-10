const user = require("./../../model/User");
const jwt = require("jsonwebtoken");
module.exports.checkaccount = async (req, res, next) => {
  const response = {};
  const authorizationHeader = req.get("Authorization");
  const token = authorizationHeader && authorizationHeader?.split(" ")[1];
  if (!token) {
    Object.assign(response, {
      state: 401,
      message: "Unthorization",
    });
  } else {
    try {
      const decode = jwt.verify(token, process.env.JWT_SECRET); // bỏi vì mình mã hóa có 2 giá trị
      const users = await user
        .findOne({ _id: decode.userId })
        .select("-password -refresh_token");
      if (!users) {
        throw new Error("User not exist ");
      }
      res.locals.user = users;
      res.locals.exp = decode.exp;
      return next();
    } catch (e) {
      console.log("chương trình đang bị lỗi ");
      Object.assign(response, {
        state: 401,
        message: "Unthorization",
      });
      return res.status(response.state).json(response);
    }
  }
};
