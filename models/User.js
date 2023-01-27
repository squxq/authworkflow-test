const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
// validator validates and sanitizes strings only
const validator = require("validator")

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Please provide name"],
      minlength: 3,
      maxlength: 50,
    },
    email: {
      type: String,
      unique: true,
      required: [true, "Please provide email"],
      validate: {
        validator: validator.isEmail,
        message: "Please provide valid email",
      },
    },
    password: {
      type: String,
      required: [true, "Please provide password"],
      minlength: 6,
    },
    role: {
      type: String,
      enum: ["admin", "user"],
      default: "user",
    },

    verificationToken: String,

    isVerified: {
      type: Boolean,
      default: false,
    },
    verified: Date,

    passwordToken: String,
    passwordTokenExpirationDate: {
      type: Date,
    },
  },
  { timestamps: true }
)

UserSchema.pre("save", function (next) {
  if (!this.isModified("password")) return next()
  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      console.log(`Server hashing functionality is failing: ${err.message}`)
      next(err)
    } else {
      bcrypt.hash(this.password, salt, (err, password) => {
        if (err) {
          console.log(
            `${this.email} was not able to hash his password: ${err.message}`
          )
          next(err)
        } else {
          this.password = password
          next()
        }
      })
    }
  })
})

UserSchema.methods.comparePassword = async function (canditatePassword) {
  const isMatch = await bcrypt.compare(canditatePassword, this.password)
  return isMatch
}

module.exports = mongoose.model("User", UserSchema)
