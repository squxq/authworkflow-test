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

UserSchema.pre("save", () => {
  if (!this.isModified("password")) return
  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      console.log(`Server hashing functionality is failing: ${err.message}`)
    } else {
      bcrypt.hash(this.password, salt, (err, password) => {
        if (err) {
          console.log(
            `${this.email} was not able to hash his password: ${err.message}`
          )
        } else {
          this.password = password
        }
      })
    }
  })
})

UserSchema.methods.comparePassword = (candidatePassword) => {
  bcrypt.compare(candidatePassword, this.password, (err, result) => {
    if (err) {
      console.log(
        `The server could not verify the password. User cannot be logged in. Please try again later.`
      )
    } else {
      return result
    }
  })
}
module.exports = mongoose.model("User", UserSchema)
