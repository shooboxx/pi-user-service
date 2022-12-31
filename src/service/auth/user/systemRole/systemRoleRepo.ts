import { SystemRole } from "./authTypes"
import db from "../../../../models";

const findRoleId = async (roleName : string) => {
    const role = await db.SystemRole.findOne({ where: {role_name: roleName}})
    if (!role) return null

    return role.dataValues.id
}
const findRole = async (roleId : number) => {
    const role = await db.SystemRole.findOne({ where: {id: roleId}})
    if (!role) return null

    return role.dataValues
}

const setUserRole = async (userId, roleName) => {

}

module.exports = { findRoleId, findRole}