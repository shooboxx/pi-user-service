export interface User {
    id: number,
    role_id: number,
    first_name: string,
    last_name: string,
    email_address: string,
    password: string,
    dob: string,
    gender?: string,
    profile_picture_url?: string,
    country: string,
    city?: string,
    primary_phone?: string,
    state?: string,
    is_verified: boolean,
    verify_token?: string,
    verify_expires?: Date,
    active: boolean,
    reset_token?: string,
    reset_expires?: Date
    password_last_updated?: number
    deleted_date?: Date
    insert_date?: Date,
    update_date?: Date,
}

// Super details about a user
// interface UserDetail {
//     user: User,
//     business: Business[]
//     activities: Activity[]
// }