export {};
import db from "../../models";
import { User } from "./userType";
const { Op } = require("sequelize");

const addUser = async (user: User) => {
  const {dataValues} = await db.Users.create({
    email_address: user.email_address,
    password: user.password,
    system_role_id: user.role_id,
    first_name: user.first_name,
    last_name: user.last_name,
    verify_token: user.verify_token,
    gender: user.gender,
    country: user.country,
    city: user.city,
    state: user.state,
    date_of_birth: user.dob,
    primary_phone_contact: user.primary_phone,
    active: true,
    is_verified: user.is_verified,
    verify_expires: user.verify_expires
  }).catch(() => null)
  return dataValues;
};

const findUser = async (userId: number, emailAddress: string) => {
  const user = await db.Users.findOne({ where: {
      [Op.or]: [{email_address: emailAddress, deleted_date: null}, { id: userId, deleted_date: null}]}
  });  
  if (!user) {
    return null;
  }
  return user.dataValues;
};

const findUserByResetToken = async (resetToken: string) => {
  const user = await db.Users.findOne({ where: { reset_token: resetToken, deleted_date: null } });
  if (!user) return null;

  return user.dataValues;
};

const findUserByVerificationToken = async (verifyToken: string) => {
  const user = await db.Users.findOne({ where: { verify_token: verifyToken, deleted_date: null } });
  if (!user) return null;

  return user.dataValues;
};

const updateUser = async (user: User) => {
  await db.Users.update(
    {
      first_name: user.first_name,
      last_name: user.last_name,
      date_of_birth: user.dob,
      gender: user.gender,
      profile_picture_url: user.profile_picture_url,
      country: user.country,
      city: user.city,
      primary_phone_contact: user.primary_phone,
      state: user.state,
      is_verified: user.is_verified,
      active: user.active,
    },
    {
      where: {
        id: user.id,
        deleted_date: null
      },
    }
  );
  return user;
};

const deleteUser = async (user: User) => {
  await db.Users.update(
    {
      deleted_date: user.deleted_date
    },
    {
      where: {
        id: user.id,
        deleted_date: null
      },
    }
  );
  return user;
};

const storeRefreshToken = async (user_id: number, refreshToken: string) => {
  const { dataValues } = await db.UserTokens.create({
    user_id: user_id,
    refresh_token: refreshToken,
    insert_date: new Date()
  }).catch((e)=> {throw e});

  return dataValues
};

const findRefreshToken = async (refreshToken: string) => {
  const token = await db.UserTokens.findOne({
    where: {refresh_token: refreshToken },
  });
  if (!token) {
    return null;
  }
  return token.dataValues;
};

const clearRefreshTokens = async (userId) => {
  await db.UserTokens.destroy({
    where: {
      user_id: userId,
    },
  });
};
const deleteRefreshToken = async (token) => {
  await db.UserTokens.destroy({
    where: {
      refresh_token: token
    },
  }).catch((e)=> {throw e});
};

const updateUserPassword = async (userId : number, hashedPassword : string) => {
  await db.Users.update({
    password: hashedPassword
  },
  {  
    where: {
    id: userId
    }
  })
}
const updateUserResetToken = async (userId : number, resetToken : string, resetTokenExpiry : Date | null) => {
  await db.Users.update({
    reset_token: resetToken,
    reset_expires: resetTokenExpiry
  }, {
    where: {
      id: userId
    }
  })
}

// TODO: Create a function that hard delete user accounts
//TODO: Create reset token + reset expiry

module.exports = {
  addUser,
  findUser,
  findUserByResetToken,
  updateUser,
  findUserByVerificationToken,
  storeRefreshToken,
  findRefreshToken,
  clearRefreshTokens,
  deleteRefreshToken,
  updateUserPassword,
  updateUserResetToken,
  deleteUser
};
