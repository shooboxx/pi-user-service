export {}
const express = require('express');
const router = express.Router()
const userService = require('../user/userService')
import { User } from "./userType";
import { UserAuthentication } from '../auth/user/userAuthenticationService';
const { checkNotAuthenticated, authenticateToken } = require('../auth/user/userAuthorization')
import {sendVerificationEmail, sendResetEmail} from '../email/emailService'

function cleanUserDetails(user) {
    let {password, deleted_date, ...cleanedUserDetails} = user
    return cleanedUserDetails
}

router.get('/users', async (req, res) => {
    let user = {}
    const {id, email} = req.query
    try {
        if (id) user = await userService.getUserById(id)
        if (email) user = await userService.getUserByEmail(email)
        return res.status(200).json(cleanUserDetails(user))
    }
    catch (e : any) {
        res.status(400).json({"error": e.message})
    }
})
router.post('/users', checkNotAuthenticated, async (req: any, res: any) => {
    try {
        const newUser = await UserAuthentication.register(req.body)
        const verificationLink = `${req.headers.origin}/verify?token=${newUser.verify_token}`
        process.env.NODE_ENV !== 'development' && await sendVerificationEmail({first_name: newUser.first_name, verify_link: verificationLink, email_to: newUser.email_address})

        return res.status(200).json({first_name: newUser.first_name, verify_link: verificationLink, email_to: newUser.email_address})
    }
    catch (err: any) {
        return res.status(400).json({ error: err.message })
    }

});

router.get('/user', authenticateToken, async (req, res) => {
    try {
        const user = await userService.getUserById(req.user_id)
        return res.status(200).json(cleanUserDetails(user))
    }
    catch (e : any) {
        res.status(400).json({"error": e.message})
    }
})

router.delete('/user', authenticateToken, async (req, res) => {
    try {
        return res.status(200).json(await userService.deleteUser(req.user_id))
    }
    catch (e : any) {
        res.status(400).json({"error": e.message})
    }
})
router.put('/user', authenticateToken, async (req, res) => {
    try {
        const user = {
            id: req.user_id,
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            dob: req.body.dob,
            gender: req.body.gender,
            country: req.body.country,
            city: req.body.city,
            primary_phone: req.body.primary_phone,
            state: req.body.state,
        }
        const updatedUser = await userService.updateUserProfile(cleanUserDetails(user))
        return res.status(200).json(updatedUser)
    }
    catch (e : any) {
        res.status(400).json({"error": e.message})
    }
})

router.get('/user/verify', async (req: any, res: any) => {
    try {
        const verified : User = await userService.verifyUser(req.query.token)
        if (verified) return res.status(200).json({success: true})
    }
    catch (err : any){
        return res.status(400).json({ error: err.message })
    }
    res.sendStatus(400)
})

router.post('/user/login', checkNotAuthenticated, async (req, res) => {
    try {

        const user = await UserAuthentication.login(req.body.email_address, req.body.password)
        await userService.storeRefreshToken(user.id, user.hashed_refresh_token).catch((e)=> {throw e})
        res.cookie("access_token", user.access_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV == 'production' ? true : false,
            sameSite: process.env.NODE_ENV == 'production' && 'None',
        })
        res.cookie("refresh_token", user.refresh_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV == 'production' ? true : false,
            sameSite: process.env.NODE_ENV == 'production' && 'None',
        })
        res.setHeader('Access-Control-Allow-Credentials', true);   
        
        return res.status(200).json({ "success" : true })
    }
    catch (e: any) {
        return res.status(e.statusCode || 400).json({ "error": e.message })
    }
})

router.delete('/user/logout', async (req: any, res: any) => {
    console.log(req.cookies['refresh_token'])
    await UserAuthentication.logout(req.cookies['refresh_token'])
    res.clearCookie("access_token");
    res.clearCookie("refresh_token");
    return res.status(204).json({"success": true})
});

router.post('/user/forgot-password', checkNotAuthenticated, async (req: any, res: any) => {
    try {
        const user = await UserAuthentication.forgotPasswordRequest(req.body.email_address)
        if (!user?.resetToken) return res.status(200).json({})

        const resetPasswordLink = `${req.headers.origin}/reset-password/${user.resetToken}`
        process.env.NODE_ENV !== 'development' && await sendResetEmail({first_name: user.firstName, reset_link: resetPasswordLink, email_to: user.emailAddress})

        return res.status(200).json({first_name: user.firstName, reset_link: resetPasswordLink, email_to: user.emailAddress})
    }
    catch (err: any) {
        return res.status(400).json({ "error": err.message })
    }

});

router.post('/user/reset-password/:resetToken', checkNotAuthenticated, async (req: any, res: any) => {
    try {
        UserAuthentication.resetPassword(req.params.resetToken, req.body.password, req.body.password_confirm)
        return res.status(200).send({success: true})
    }
    catch (e: any) {
        return res.status(400).send(e.message)
    }
});

router.post('/user/refresh-token', async (req, res) => {
    const refreshToken = req.cookies.refresh_token
    const accessToken = await UserAuthentication.refreshAccessToken(refreshToken)
    if (!accessToken) {
        UserAuthentication.logout(refreshToken)
        return res.sendStatus(403)
    }
    res.cookie("access_token", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV == 'production' ? true : false,
        sameSite: process.env.NODE_ENV == 'production' && 'None',
    })
    return res.status(204).json({ success: true })
})

router.put('/user/change-password', authenticateToken, async (req, res) => {
    try {
    const currentPassword = req.body.current_password
    const newPassword = req.body.new_password
    const newPasswordConfirm = req.body.new_password_confirm
    if ((currentPassword === newPassword) || (currentPassword === newPasswordConfirm) ) return res.json({ success: true })
    
    const foundUser = await userService.getUserById(req.user_id)
    const user = await UserAuthentication.login(foundUser.email_address, currentPassword)
    await UserAuthentication.changePassword(user.id, newPassword, newPasswordConfirm)
    return res.json({ success: true })
    
    }
    catch (e : any) {
        return res.status(400).send({error: e.message})
    }
})

// TODO: Add an upload profile photo route
// TODO: Add a Remove profile photo route

module.exports = router