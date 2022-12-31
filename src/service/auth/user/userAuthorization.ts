// Define roles and create middlewares that control authorization within the application
const jwt = require('jsonwebtoken')
import AppError from '../../../utils/appError.js'
import { AuthErrors } from './authConst'

function authenticateToken (req, res, next) {
    const token = req.cookies.access_token
    if (token == null) throw new AppError(AuthErrors.LoginRequired, 403)
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) throw new AppError(AuthErrors.InvalidToken, 401)
        req.user_id = user.user_id
        return next()
    })
}

function checkNotAuthenticated (req, res, next) {
    const token = req.cookies.access_token
    
    if (token === undefined || token === null) {
        return next()
    }
    
    return res.status(403).json({"error": AuthErrors.AlreadyLoggedIn})
}
module.exports = {authenticateToken, checkNotAuthenticated}