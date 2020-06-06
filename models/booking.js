const mongoose = require("mongoose");

const Schema = mongoose.Schema;

// {timestamps: true} is for mongoose to automatically
// add a created at and updated at keys in our database for bookings
const bookingSchema = new Schema(
  {
    event: {
      type: Schema.Types.ObjectId,
      ref: "Event",
    },
    user: {
      type: Schema.Types.ObjectId,
      ref: "User",
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Booking", bookingSchema);
