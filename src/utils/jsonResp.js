function jsonRes(json){
    return {
        status: "success",
        data: {json}
    }
}

module.exports = jsonRes