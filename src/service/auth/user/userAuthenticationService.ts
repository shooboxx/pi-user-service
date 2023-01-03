import {UserService} from '../../user/userService'
import { User } from "./../../user/userType";
import AppError from "../../../utils/appError.js";
import { AuthErrors } from "./authConst";
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const systemRoleService = require('./systemRole/systemRoleService')

const login = async (emailAddress: string, password : string) => {
    const user : User = await UserService.getUserByEmail(emailAddress)
    if (!user) throw new AppError(AuthErrors.IncorrectLogin, 400)
    
    const passwordsMatched = await bcrypt.compare(password, user.password) 
    if (!passwordsMatched) throw new AppError(AuthErrors.IncorrectLogin, 400)
    
    const access_token = _generateAccessToken({ user_id: user.id })
    const refresh_token = jwt.sign({ user_id: user.id }, process.env.REFRESH_TOKEN_SECRET)
    const hashed_refresh_token = _hashToken(refresh_token)
    
    return { id: user.id, access_token: access_token, refresh_token, hashed_refresh_token }

}

const register = async (user) : Promise<User>=> {
    const hashedPass = await _generatePasswordHash(user['password'])
    const buildUser: User = {
        id: 1,
        role_id: await systemRoleService.getRoleId('USER'),
        first_name: user.first_name,
        last_name: user.last_name,
        email_address: user.email_address.toLowerCase(),
        password: hashedPass,
        dob: user.dob,
        state: user.state,
        city: user.city,
        country: user.country,
        primary_phone: user.primary_phone,
        gender: user.gender,
        active: true,
        is_verified: false,
        verify_token: crypto.randomBytes(32).toString('hex')

    }
    return await UserService.createUser(buildUser)
}

const forgotPasswordRequest = async (emailAddress : string) => {
    let user: User = await UserService.getUserByEmail(emailAddress)
    if (!user) return {id: 0, firstName: '', emailAddress: '', resetToken: '', userResetTokenExpiry: null}

    const resetExpiryTime = new Date().getTime() + 10 * 60000

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedResetToken = _hashToken(resetToken)
    const userResetTokenExpiry = new Date(resetExpiryTime);

    UserService.updateResetToken(user.id, hashedResetToken, userResetTokenExpiry);
    return {id: user.id, firstName: user.first_name, emailAddress: user.email_address, resetToken, userResetTokenExpiry}
}

const resetPassword = async (resetToken : string, newPassword : string, newPasswordConfirm : string) => {
    const hashedResetToken = _hashToken(resetToken)
    const user: User = await UserService.getUserByResetToken(hashedResetToken)

    if (!user) throw new AppError(AuthErrors.BadResetToken, 400)

    if (user.reset_expires! < new Date()) {
        throw new AppError(AuthErrors.TokenExpired, 401)
    }
    await UserService.updatePassword(user.id, newPassword, newPasswordConfirm)
    await UserService.updateResetToken(user.id, '', null)
    return true
}

const changePassword = async (userId : number, newPassword : string, newPasswordConfirm : string) => {
    await UserService.updatePassword(userId, newPassword, newPasswordConfirm).catch(err => {throw err})
    return true
}

const refreshAccessToken = async (refreshToken : string) : Promise<String>=> {
    let accessToken = ''
    if (!refreshToken) return accessToken
    
    const hashedToken = _hashToken(refreshToken) 
    const token = await UserService.findRefreshToken(hashedToken).catch( err => { throw err })
    
    if (!token) return accessToken

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return accessToken
        accessToken =  _generateAccessToken({ user_id: user.user_id })
    })
    return accessToken
}

const logout = async (refreshToken : string) => {
    if (!refreshToken) return true
    const hashedToken = _hashToken(refreshToken)
    await UserService.deleteRefreshToken(hashedToken)
    return true
}

function _generateAccessToken(tokenInfo) {
    return jwt.sign(tokenInfo, process.env.ACCESS_TOKEN_SECRET, { expiresIn: process.env.NODE_ENV == 'development' ? '1440m' : '120m' })
}

const _generatePasswordHash = async (password : string) : Promise<string> => {
    return await bcrypt.hash(password, 10)
}

const _hashToken = (token : string) => {
    return crypto.createHash('sha256').update(token).digest('hex')
}


export const UserAuthentication = {
    login,
    register, 
    forgotPasswordRequest,
    resetPassword,
    refreshAccessToken,
    logout,
    changePassword,
}