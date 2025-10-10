const mongoose = require("mongoose");
module.exports.connect = () => {
  try {
    mongoose
      .connect(process.env.MONGODB_URL)
      .then(() => console.log("Connected!")); // đã kết nối thành công
  } catch (error) {
    console.log("error:", error);
  }
};
