const User = require("../models/User")
const Token = require("../models/Token")
const { StatusCodes } = require("http-status-codes")
const crypto = require("crypto")
const CustomError = require("../errors")
const { sendVerificationEmail } = require("../utils/sendVerificationEmail")

const register = (req, res) => {
  const { email, name, password } = req.body
  User.findOne({ email }, async (err, user) => {
    if (err) {
      throw new CustomError.ServerError("DB could not be searched...")
    } else if (user) {
      throw new CustomError.BadRequestError("Email already exists...")
    }

    // first registered user is an admin
    const isFirstAccount = (await User.countDocuments({})) === 0
    const role = isFirstAccount ? "admin" : "user"

    const verificationToken = crypto.randomBytes(40).toString("hex")

    User.create(
      {
        name,
        email,
        password,
        role,
        verificationToken,
      },
      (err, newUser) => {
        if (err) {
          throw new CustomError.ServerError("User could not be created...")
        }
        const protocol = req.protocol
        const host = req.get("host")

        sendVerificationEmail({
          name: newUser.name,
          email: newUser.email,
          verificationToken: newUser.verificationToken,
          origin: `${protocol}://${host}`,
        })

        res.status(StatusCodes.CREATED).json({
          msg: "Success! Please check tou e-mail to verify account...",
        })
      }
    )
  })
}

module.exports = { register }
