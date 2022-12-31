import { SystemRole } from "./authTypes"
const systemRoleRepo = require('./systemRoleRepo')
const userService = require('../../../user/userService')
import { User } from '../../../user/userType'

const getRoleId = async (roleName) : Promise<number> => {
    if (!roleName) throw Error('role_name is required') 
    const roleId = await systemRoleRepo.findRoleId(roleName)
    if (!roleId) throw Error("Role not found with that name")

    return roleId
}
const getRole = async (roleId) : Promise<SystemRole> => {
    if (!roleId) throw Error('role_id is required') 
    const role= await systemRoleRepo.findRole(roleId)
    if (!role) throw Error("Role not found with that ID")

    return role
}

const getUserRole = async (userId) : Promise<SystemRole> => {
    const user : User = userService.getUserById(userId)
    const role : SystemRole = await getRole(user.role_id)
    if (!role) throw new Error('role not found')

    return role
}

const setUserRole = async (userId, roleName) => {
    const roleId = await getRoleId(roleName)
    systemRoleRepo.setUserRole(userId, roleId)
}


module.exports = {getRoleId, getRole, getUserRole}