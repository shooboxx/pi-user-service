const sgMail = require('@sendgrid/mail')

interface EmailContent {
    to: string,
    from: string,
    subject: string,
    text: string,
    html: string
}

export function sendEmail(msg : EmailContent) : Boolean {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY)
    sgMail
    .send(msg)
    .then(() => {
        return true
    })
    .catch((error) => {
        return false
    })
    return true

}

