import axios from 'axios'

export const sendVerificationEmail = async (data) => {
   return await axios.post('https://api.sendgrid.com/v3/mail/send', {
        "from":{
           "email":"noreply@theproductindex.io",
           "name": "Product Index"
        },
        "personalizations":[
           {
              "to":[
                 {
                    "email":data.email_to
                 }
              ],
              "dynamic_template_data":{
                 "first_name":data.first_name,
                 "verification_link": data.verify_link
             }
           }
        ],
        "template_id": process.env.SENDGRID_VERIFICATION_EMAIL_TEMPLATE_ID
     }, {
        headers: {
            "Authorization": `Bearer ${process.env.SENDGRID_API_KEY}`,
            'Content-Type': 'application/json'
         }
     })
    
}

export const sendResetEmail = async (data) => {
   return await axios.post('https://api.sendgrid.com/v3/mail/send', {
        "from":{
           "email":"noreply@theproductindex.io",
           "name": "Product Index"
        },
        "personalizations":[
           {
              "to":[
                 {
                    "email":data.email_to
                 }
              ],
              "dynamic_template_data":{
                 "first_name":data.first_name,
                 "reset_link": data.reset_link
             }
           }
        ],
        "template_id": process.env.SENDGRID_RESET_EMAIL_TEMPLATE_ID
     }, {
        headers: {
            "Authorization": `Bearer ${process.env.SENDGRID_API_KEY}`,
            'Content-Type': 'application/json'
         }
     })
    
}
