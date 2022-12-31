const getCurrentAge = birthday => {
    return Math.floor((new Date().valueOf() - new Date(birthday).getTime()) / 3.15576e+10)
}
module.exports = getCurrentAge