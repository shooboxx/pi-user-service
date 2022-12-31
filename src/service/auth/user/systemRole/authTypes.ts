export interface SystemRole {
    id: number,
    role_name: string,
    access_level: number,
    update_date: number,
    insert_date: number
}

// ROLES {
// 0: Unlimited, 1: Admin, 2: Moderator, 3: Tester, 4: Beta User, 5: User, 6: Anonymous
// }