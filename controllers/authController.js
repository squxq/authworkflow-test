const User = require("../models/User")
const Token = require("../models/Token")
const { StatusCodes } = require("http-status-codes")
const crypto = require("crypto")
const CustomError = require("../errors")
const {
  attachCookiesToResponse,
  sendVerificationEmail,
  createTokenUser,
  sendResetPasswordEmail,
  createHash,
} = require("../utils")
const jwt = require("jsonwebtoken")

const register = (req, res) => {
  const { email, name, password } = req.body

  if (!email || !name || !password)
    throw new CustomError.BadRequestError("All fields are required...")

  User.findOne({ email }, async (err, user) => {
    if (err) {
      throw new CustomError.ServerError(
        `DB could not be searched... \n ${err.message}`
      )
    } else if (user) {
      throw new CustomError.ConflictError("Email already exists...")
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
          throw new CustomError.ServerError(
            `User could not be created... \n ${err.message}`
          )
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
          // token: newUser.verificationToken,
        })
      }
    )
  })
}

const verifyEmail = (req, res) => {
  const { verificationToken, email } = req.body

  User.findOne({ email }, async (err, user) => {
    if (err) {
      throw new CustomError.ServerError(
        `DB could not be searched... \n ${err.message}`
      )
    } else if (!user) {
      throw new CustomError.UnauthenticatedError(
        "Verification failed. User not found..."
      )
    } else if (user.verificationToken !== verificationToken) {
      throw new CustomError.UnauthenticatedError(
        "Verification failed. Invalid token..."
      )
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

const handleTokens = (req, res) => {
  // const { refreshToken } = req.signedCookies
  // for postman
  const { refreshToken } = req.body
  if (!refreshToken)
    throw new CustomError.UnauthenticatedError("No cookie was provided...")

  res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true })

  Token.findOne({ refreshToken }, (err, token) => {
    if (err)
      throw new CustomError.ServerError(
        `Couldn't search the DB... \n ${err.message}`
      )
    if (!token) {
      jwt.decode(refreshToken, (err, decoded) => {
        // err if we can't decode the token
        if (err)
          throw new CustomError.UnauthorizedError(
            "Token could not be decoded..."
          )
        // if !err its a reuse attempt
        Token.deleteMany({ user: decoded.userId }, (err) => {
          if (err)
            throw new CustomError.ServerError(
              `Tokens could not be deleted... \n ${err.message}`
            )
        })
      })
      return res.status(StatusCodes.FORBIDDEN).json({
        msg: "Clients are not allowed to perform this action...",
      })
    }

    User.findOne({ _id: token.user }, (err, user) => {
      if (err)
        throw new CustomError.ServerError(
          `DB could not be searched... \n ${err.message}`
        )

      jwt.verify(refreshToken, process.env.JWT_SECRET, (err, decoded) => {
        console.log(user._id, decoded)
        if (err) {
          Token.findOneAndDelete({ _id: token._id }, (err, docs) => {
            if (err)
              throw new CustomError.ServerError(
                `Token could not be deleted... \n ${err.message}`
              )
          })
        }
        // if (err || user._id !== decoded.userId)
        // throw new CustomError.UnauthorizedError("Invalid token...")

        const tokenUser = createTokenUser(user)

        // refresh token was still valid
        const newRefreshToken = crypto.randomBytes(40).toString("hex")
        const userAgent = req.headers["user-agent"]
        const ip = req.ip
        const userToken = {
          refreshToken: newRefreshToken,
          ip,
          userAgent,
          user: user._id,
        }

        Token.create(userToken, (err, newUserToken) => {
          if (err) {
            throw new CustomError.ServerError(
              "DB was not able to create the token..."
            )
          }

          attachCookiesToResponse({ res, user: tokenUser, newRefreshToken })

          res.status(StatusCodes.OK).json({ user: tokenUser, newRefreshToken })
        })
      })
    })
  })
}

const login = (req, res) => {
  // const { refreshToken } = req.signedCookies
  // for postman
  const { refreshToken } = req.body
  const { email, password } = req.body

  if (!email || !password) {
    throw new CustomError.BadRequestError(
      "Please provide email and password..."
    )
  }

  User.findOne({ email }, async (err, user) => {
    if (err) {
      throw new CustomError.ServerError(
        `DB could not be searched... \n ${err.message}`
      )
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

      if (refreshToken) {
        Token.findOneAndDelete({ refreshToken }, (err, deletedToken) => {
          if (err)
            throw new CustomError.ServerError(
              `DB could not delete token... \n ${err.message}`
            )
        })
        res.cookie("refreshToken", "logout", {
          httpOnly: true,
          expires: new Date(Date.now()),
        })
      }

      // creates an object with name, id and role fields for each user
      const tokenUser = createTokenUser(user)
      // create refresh token
      const newRefreshToken = crypto.randomBytes(40).toString("hex")
      const userAgent = req.headers["user-agent"]
      const ip = req.ip
      const userToken = {
        refreshToken: newRefreshToken,
        ip,
        userAgent,
        user: user._id,
      }

      Token.create(userToken, (err, newUserToken) => {
        if (err) {
          throw new CustomError.ServerError(
            `DB was not able to create the token... \n ${err.message}`
          )
        }

        attachCookiesToResponse({ res, user: tokenUser, newRefreshToken })

        res.status(StatusCodes.OK).json({ user: tokenUser, newRefreshToken })
      })
    }
  })
}

const logout = (req, res) => {
  Token.findOneAndDelete({ user: req.user.userId })
  // const { refreshToken } = req.signedCookies
  // for postman
  const { refreshToken } = req.body

  res.cookie("accessToken", "logout", {
    httpOnly: true,
    expires: new Date(Date.now()),
  })

  // is refresh token in DB
  Token.findOne({ refreshToken }, (err, token) => {
    if (err)
      throw CustomError.ServerError(
        `DB could not search for the token... \n ${err.message}`
      )
    if (token) {
      Token.findOneAndDelete({ refreshToken }, (err, deletedToken) => {
        if (err)
          throw new CustomError.ServerError(
            `Token not deleted... \n ${err.message}`
          )
      })
    }
    res.cookie("refreshToken", "logout", {
      httpOnly: true,
      expires: new Date(Date.now()),
    })
    return res
      .status(StatusCodes.NO_CONTENT)
      .json({ msg: "No token. Logout successful" })
  })

  res.status(StatusCodes.OK).json({ msg: "User logged out!" })
}

const forgotPassword = (req, res) => {
  const { email } = req.body
  if (!email) {
    throw new CustomError.BadRequestError("Please provide a valid e-mail...")
  }

  User.findOne({ email }, async (err, user) => {
    if (err) {
      throw new CustomError.ServerError("DB could not be searched...")
    } else if (!user) {
      throw new CustomError.UnauthenticatedError("Invalid credentials...")
    }

    const passwordToken = crypto.randomBytes(70).toString("hex")
    // send email

    const protocol = req.protocol
    const host = req.get("host")

    await sendResetPasswordEmail({
      name: user.name,
      email: user.email,
      token: passwordToken,
      origin: `${protocol}://${host}`,
    })

    const passwordTokenExpirationDate = new Date(Date.now() + 600000)
    user.passwordToken = createHash(passwordToken)
    user.passwordTokenExpirationDate = passwordTokenExpirationDate

    await user.save()

    res.status(StatusCodes.OK).json({
      msg: "Please check you e-mail for reset password link...",
      token: passwordToken,
    })
  })
}

const resetPassword = (req, res) => {
  const { token, email, password } = req.body

  if (!token || !email || !password) {
    throw new CustomError.BadRequestError("Email already exists...")
  }

  User.findOne({ email }, async (err, user) => {
    if (err) {
      throw new CustomError.ServerError("DB could not be searched...")
    } else if (!user) {
      throw new CustomError.UnauthenticatedError("Invalid credentials...")
    }

    const currentDate = new Date()

    if (
      user.passwordToken === createHash(token) &&
      user.passwordTokenExpirationDate > currentDate
    ) {
      user.password = password
      user.passwordToken = null
      user.passwordTokenExpirationDate = null
      await user.save()

      return res.status(StatusCodes.OK).json({
        msg: "Password reseted successfully...",
      })
    }

    throw new CustomError.BadRequestError("Invalid credentials...")
  })
}

module.exports = {
  register,
  handleTokens,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
}
