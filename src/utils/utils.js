
// Checks to see if object or array isn't empty.
function exist(obj) {
    if (Object.keys(obj).length === 0 && obj.constructor === Object)
    { return false}
    if (obj.length === 0){ return false}
    return true
}

module.exports = {exist}