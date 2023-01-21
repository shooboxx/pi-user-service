function cleanPhoneNumber(phoneNumber) {
    let cleanNumber = []
    for (let i in phoneNumber) {
        if (!isNaN(phoneNumber[i])) cleanNumber.push(phoneNumber[i])
    }
    if (cleanNumber.join('').length === 10) return cleanNumber.join('')
    throw Error('Not a valid phone number')
}

module.exports = cleanPhoneNumber