import { User } from "./userType";
import AppError from "../../utils/appError.js";
import cleanPhoneNumber from "../../utils/cleanPhoneNumber.js";
const bcrypt = require("bcrypt");
const userRepo = require("./userRepo");
import { UserErrors } from "./userConst";
import getCurrentAge from "../../utils/getCurrentAge"
import {Genders} from './enums/gender'
let emailValidator = require("email-validator");
const {getName} = require('country-list');

const getUserByEmail = async (emailAddress: string) => {
  if (!emailAddress) throw new AppError(UserErrors.EmailAddressRequired, 400);
  return await userRepo.findUser(null, emailAddress.toLowerCase())
    .catch(err => {throw new AppError(err, 400)});
};

// Returns user without password (for internal use)
const getUserById = async (userId: number) => {
  if (!userId)  throw new AppError(UserErrors.UserIdRequired, 400);
  return await userRepo.findUser(userId, null)
    .catch(err => {throw new AppError(err.message, err.statusCode) })
};

// Returns user
const getUserByVerificationToken = async (token: string) => {
  if (!token) throw new AppError(UserErrors.VerificationTokenRequired, 400);
  const foundUser = await userRepo.findUserByVerificationToken(token)
    .catch(err => {throw new AppError(err.message, err.statusCode);})
  if (!foundUser) throw new AppError(UserErrors.InvalidVerificationToken, 400);
  if (foundUser.is_verified) throw new AppError(UserErrors.UserVerified, 304)
  return foundUser
};

const getUserByResetToken = (resetToken: string): User => {
  if (!resetToken) throw new AppError(UserErrors.ResetTokenRequired, 400);
  const user : User = userRepo.findUserByResetToken(resetToken);
  if (!user) throw new AppError(UserErrors.UserNotFound, 404);
  return user;
};

const createUser = async (user: User) => {
  try {
    _validate_user_profile_completeness(user)
    const foundUser = await getUserByEmail(user.email_address);
    if (foundUser) throw new AppError(UserErrors.UserExist, 400);
    return await userRepo.addUser(user);
  
  } catch (e: any) {
    throw e;
  }
};
 
const updateUserProfile = async (user: User) => {
  try {
    if (user.primary_phone) user.primary_phone = cleanPhoneNumber(user.primary_phone)
    if (user.dob && getCurrentAge(user.dob) < 15) throw new AppError(UserErrors.AgeMinimumRequirement, 400)
    if (user.gender && !Genders[user.gender]) throw new AppError(UserErrors.GenderNotListed)
    if (user.country && !getName(user.country.toUpperCase().trim())) throw new AppError(UserErrors.InvalidCountry)
    user.country = getName(user.country.toUpperCase().trim())
    return await userRepo.updateUser(user).catch(err => {throw err});
  }
  catch (e : any) {
    throw new AppError(e.message, e.statusCode)
  }

};

const updateResetToken = async (userId : number, resetToken : string, resetTokenExpiry : Date | null) => {
  return await userRepo.updateUserResetToken(userId, resetToken, resetTokenExpiry).catch(err => {throw err})
};

const updatePassword = async (userId : number, newPassword : string ,newPasswordConfirm : string) => {
  if (newPassword !== newPasswordConfirm) throw new AppError(UserErrors.PasswordsMismatch, 400);
  if (newPassword.length < 8) throw new AppError(UserErrors.PasswordComplexityRequirement, 400)
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  const updatedUser = userRepo.updateUserPassword(userId, hashedPassword).catch(err => { throw err  })
  if (updatedUser) userRepo.clearRefreshTokens(userId).catch(err => { throw err });
  return true;
};

const verifyUser = async (token: string) => {
    if (!token) throw new Error(UserErrors.VerificationTokenRequired);
    const user: User = await getUserByVerificationToken(token);

    user.is_verified = true;
    user.verify_token = '';
    userRepo.updateUser(user).catch(err => {throw err});
    return true

};

const deleteUser = async (userId: number) => {
    const user : User = await getUserById(userId);

    user.deleted_date = new Date();
    await userRepo.deleteUser(user).catch( err => {throw err});
    return true
};

const storeRefreshToken = async (userId: number, refreshToken: string) => {
  if (!refreshToken) throw new AppError(UserErrors.RefreshTokenRequired, 400);
  if (!userId) throw new AppError(UserErrors.UserIdRequired, 400);
  return await userRepo.storeRefreshToken(userId, refreshToken);
};

const findRefreshToken = async (refreshToken: string) => {
  return await userRepo.findRefreshToken(refreshToken);
};

const deleteRefreshToken = async(token) => {
  return await userRepo.deleteRefreshToken(token)
}

const _validate_user_profile_completeness = (user) => {
  if (!user.email_address) throw new AppError(UserErrors.EmailAddressRequired, 400);
  if (!emailValidator.validate(user.email_address.toLowerCase().trim())) throw new AppError(UserErrors.EmailAddressInvalid, 400)
  if (!user.password) throw new AppError(UserErrors.PasswordRequired, 400);
  if (!user.first_name) throw new AppError(UserErrors.FirstNameRequired, 400)
  if (user.first_name.trim().length < 2) throw new AppError(UserErrors.FirstNameMinRequirement, 400)
  if (!user.last_name) throw new AppError(UserErrors.LastNameRequired, 400)
  if (user.last_name.trim().length < 2) throw new AppError(UserErrors.LastNameMinRequirement, 400)
  if (!user.gender) throw new AppError(UserErrors.GenderRequired, 400)
  if (!Genders[user.gender]) throw new AppError(UserErrors.GenderNotListed)
  if (!user.dob) throw new AppError(UserErrors.DOBRequired, 400)
  if (getCurrentAge(user.dob) < 15) throw new AppError(UserErrors.AgeMinimumRequirement, 400)
  if (!user.country) throw new AppError(UserErrors.CountryRequired, 400)
  if (user.country && !getName(user.country.toUpperCase().trim())) throw new AppError(UserErrors.InvalidCountry, 400)
  return true
}

export const UserService = {
  getUserByEmail,
  getUserById,
  createUser,
  updateResetToken,
  updatePassword,
  getUserByResetToken,
  deleteUser,
  updateUserProfile,
  verifyUser,
  storeRefreshToken,
  findRefreshToken,
  deleteRefreshToken
};
