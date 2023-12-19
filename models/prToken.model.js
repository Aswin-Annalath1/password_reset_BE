// Here model is to store resetpassword token with userid and this colletion delete automatically after 1800 seconds(30 min)

const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const passwordResetTokenSchema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    ref: "users",
    required: true,
  },
  hashedPRToken: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,  //store that current time of created
    expires: 1800,      //it will delete data of this collection after 30 minutes..
  },
});

const passwordResetTokenModel = mongoose.model("passwordresettokens", passwordResetTokenSchema);

module.exports = { passwordResetTokenModel };