const CustomError = require("../errors/index")
const { isTokenValid, attachCookiesToResponse } = require("../utils")
const Token = require("../models/Token")

const authenticateUser = (req, res, next) => {
  const { refreshToken, accessToken } = req.signedCookies

  try {
    if (accessToken) {
      const payload = isTokenValid(accessToken)
      req.user = payload.user
      return next()
    }
    const payload = isTokenValid(refreshToken)

    Token.findOne(
      {
        user: payload.user.userId,
        refreshToken: payload.refreshToken,
      },
      (err, token) => {
        if (err) {
          throw new CustomError.ServerError(
            "DB could not search for the token..."
          )
        }

        if (!token || !token?.isValid) {
          throw new CustomError.UnauthenticatedError(
            "Authentication invalid..."
          )
        }

        attachCookiesToResponse({
          res,
          user: payload.user,
          refreshToken: token.refreshToken,
        })

        req.user = payload.user
        next()
      }
    )
  } catch (err) {
    throw new CustomError.UnauthenticatedError("Authentication invalid...")
  }
}

module.exports = { authenticateUser }
