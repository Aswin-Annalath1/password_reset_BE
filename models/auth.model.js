//This is the model Created to store user informations for user Authentication...

const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const authSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    firstName: {
      type: String,
      required: true,
    },
    lastName: {
      type: String,
      required: true,
    },
    hashedPassword: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }    //It gives created time and updated time ...
);

const authModel = mongoose.model("users", authSchema); //users is collection name that will be created in Db

module.exports = { authModel };