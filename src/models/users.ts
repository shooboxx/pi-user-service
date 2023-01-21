'use strict';
const {
  Model
} = require('sequelize');

export interface UsersAttributes {
  id: number;
  system_role_id: number;
  email_address: string;
  password: string;
  first_name?: string;
  last_name?: string;
  date_of_birth?: string;
  gender?: string;
  country?: string;
  city?: string;
  state?: string;
  profile_pic_url?: string;
  active?: boolean;
  is_verified?: boolean;
  verify_token?: string;
  verify_expires?: string;
  verify_changes?: Date;
  reset_token?: string;
  reset_expires?: string;
  primary_phone_contact?: string;
  deleted_date?: string;
  insert_date: Date;
  update_date?: Date;
}

module.exports = (sequelize : any, DataTypes : any) => {
  class Users extends Model<UsersAttributes>{
    id!: number;
    system_role_id!: number;
    email_address!: string;
    password!: string;
    first_name?: string;
    last_name?: string;
    date_of_birth?: string;
    gender?: string;
    country?: string;
    city?: string;
    state?: string;
    profile_pic_url?: string;
    active?: boolean;
    is_verified?: boolean;
    verify_token?: string;
    verify_expires?: string;
    verify_changes?: Date;
    reset_token?: string;
    reset_expires?: string;
    primary_phone_contact?: string;
    deleted_date?: string;
    insert_date!: Date;
    update_date?: Date;
  
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models : any) {

    }
  }
  Users.init({
    id: {
      autoIncrement: true,
      type: DataTypes.INTEGER,
      allowNull: false,
      primaryKey: true
    },
    system_role_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'system_role',
        key: 'id'
      }
    },
    email_address: {
      type: DataTypes.TEXT,
      allowNull: false
    },
    password: {
      type: DataTypes.STRING(100),
      allowNull: false
    },
    first_name: {
      type: DataTypes.STRING(50),
      allowNull: true
    },
    last_name: {
      type: DataTypes.STRING(50),
      allowNull: true
    },
    date_of_birth: {
      type: DataTypes.DATEONLY,
      allowNull: true
    },
    gender: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    country: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    city: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    state: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    profile_pic_url: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    active: {
      type: DataTypes.BOOLEAN,
      allowNull: true
    },
    is_verified: {
      type: DataTypes.BOOLEAN,
      allowNull: true
    },
    verify_token: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    verify_expires: {
      type: DataTypes.DATE,
      allowNull: true
    },
    verify_changes: {
      type: DataTypes.DATE,
      allowNull: true
    },
    reset_token: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    reset_expires: {
      type: DataTypes.DATE,
      allowNull: true
    },
    primary_phone_contact: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    deleted_date: {
      type: DataTypes.DATE,
      allowNull: true
    },
    insert_date: {
      type: DataTypes.DATE,
      allowNull: false
    },
    update_date: {
      type: DataTypes.DATE,
      allowNull: true
    }
  }, {
    sequelize,
    modelName: 'Users',
    tableName: 'users',
    schema: 'public',
    timestamps: true,
    createdAt: 'insert_date',
    updatedAt: 'update_date',
    indexes: [
      {
        name: "users_pkey",
        unique: true,
        fields: [
          { name: "id" },
        ]
      },
    ]
  });
  return Users;
};