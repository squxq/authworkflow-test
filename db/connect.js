const mongoose = require("mongoose")

const connectDB = (url) => {
  return mongoose.connect(url)
}
mongoose.set("strictQuery", true)

module.exports = connectDB
