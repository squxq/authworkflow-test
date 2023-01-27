const User = require("../models/User")
const Token = require("../models/Token")
const { StatusCodes } = require("http-status-codes")
const crypto = require("crypto")
const CustomError = require("../errors")
const {
  attachCookiesToResponse,
  sendVerificationEmail,
  createTokenUser,
} = require("../utils")

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
      async (err, newUser) => {
        if (err) {
          throw new CustomError.ServerError("User could not be created...")
        }
        const protocol = req.protocol
        const host = req.get("host")

        await sendVerificationEmail({
          name: newUser.name,
          email: newUser.email,
          verificationToken: newUser.verificationToken,
          origin: `${protocol}://${host}`,
        })

        // while testing in postman send verificationToken

        res.status(StatusCodes.CREATED).json({
          msg: "Success! Please check tou e-mail to verify account...",
          token: newUser.verificationToken,
        })
      }
    )
  })
}

const verifyEmail = (req, res) => {
  const { verificationToken, email } = req.body

  User.findOne({ email }, async (err, user) => {
    if (err) {
      throw new CustomError.ServerError("DB could not be searched...")
    } else if (!user) {
      throw new CustomError.UnauthenticatedError("Verification failed...")
    } else if (user.verificationToken !== verificationToken) {
      throw new CustomError.UnauthenticatedError("Verification failed...")
    }

    user.isVerified = true
    user.verified = Date.now()
    user.verificationToken = ""

    await user.save()

    res.status(StatusCodes.OK).json({
      msg: "Email verified...",
    })
  })
}

const login = (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    throw new CustomError.BadRequestError(
      "Please provide email and password..."
    )
  }

  User.findOne({ email }, async (err, user) => {
    if (err) {
      throw new CustomError.ServerError("DB could not be searched...")
    } else if (!user) {
      throw new CustomError.UnauthenticatedError("Invalid credentials...")
    }

    const result = await user.comparePassword(password)
    if (typeof result === "boolean") {
      if (!result) {
        throw new CustomError.UnauthenticatedError("Invalid credentials...")
      }

      if (!user.isVerified) {
        throw new CustomError.UnauthenticatedError(
          "Please verify your e-mail..."
        )
      }

      const tokenUser = createTokenUser(user)

      // create refresh token
      let refreshToken = ""
      // check for existing token
      Token.findOne({ user: user._id }, (err, token) => {
        if (err) {
          throw new CustomError.ServerError("DB could not be searched...")
        }
        if (token) {
          const { isValid } = token
          if (!isValid) {
            throw new CustomError.UnauthenticatedError("Invalid Credentials...")
          }

          refreshToken = token.refreshToken
          attachCookiesToResponse({ res, user: tokenUser, refreshToken })
          res.status(StatusCodes.OK).json({ user: tokenUser })
        } else if (!token) {
          refreshToken = crypto.randomBytes(40).toString("hex")
          const userAgent = req.headers["user-agent"]
          const ip = req.ip
          const userToken = { refreshToken, ip, userAgent, user: user._id }

          Token.create(userToken, (err, newUserToken) => {
            if (err) {
              throw new CustomError.ServerError(
                "DB was not able to create the token..."
              )
            }

            attachCookiesToResponse({ res, user: tokenUser, refreshToken })

            res.status(StatusCodes.OK).json({ user: tokenUser })
          })
        }
      })
    } else {
      throw new CustomError.ServerError(
        "Password could not be verified. User not logged in..."
      )
    }
  })
}

module.exports = { register, login, verifyEmail }
