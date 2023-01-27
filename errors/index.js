const CustomAPIError = require("./custom-api")
const UnauthenticatedError = require("./unauthenticated")
const NotFoundError = require("./not-found")
const BadRequestError = require("./bad-request")
const UnauthorizedError = require("./unauthorized")
const ServerError = require("./server-error")
module.exports = {
  CustomAPIError,
  UnauthenticatedError,
  NotFoundError,
  BadRequestError,
  UnauthorizedError,
  ServerError,
}
