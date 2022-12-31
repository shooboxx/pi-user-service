export const AuthErrors = {
    TokenExpired: "The reset token has expired. Please request a new reset token",
    BadResetToken: "Unable to find user associated with this reset token. Request another token to continue.",
    IncorrectLogin: 'Email address or password is incorrect',
    LoginRequired: 'User login is required',
    InvalidToken: 'Token invalid or expired',
    AlreadyLoggedIn: 'You are currently logged in and unable to do this request. You can logout and try again'
}