const mongoose = require("mongoose");
const userSchema = new mongoose.Schema(
  {
    fullname: String,
    email: String,
    password: String,
    phone: String,
    avatar: String,
    status: {
      type: String,
      default: "active",
    },
    deleted: {
      type: Boolean,
      default: false,
    },
    deleteAt: Date,
    resertpassword: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);
const user = mongoose.model("users", userSchema);
module.exports = user;
