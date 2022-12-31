"use strict";
const { Model } = require("sequelize");

export interface UserTokensAttributes {
  id: number;
  user_id: number;
  refresh_token: string;
  insert_date: Date;
}

module.exports = (sequelize, DataTypes) => {
    class UserTokens
      extends Model<UserTokensAttributes>
      implements UserTokensAttributes
    {
        id!: number;
        user_id!: number;
        refresh_token!: string;
        insert_date!: Date;
      
      static associate(models) {
  
      }
    }

  UserTokens.init(
    {
      id: {
        autoIncrement: true,
        type: DataTypes.INTEGER,
        allowNull: false,
        primaryKey: true
      },
      user_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
          model: 'users',
          key: 'id'
        }
      },
      refresh_token: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      insert_date: {
        type: DataTypes.DATE,
        allowNull: false
      }
    }, {
      sequelize,
      model: 'UserToken',
      tableName: 'user_tokens',
      schema: 'public',
      timestamps: false,
      createdAt: 'insert_date',
      indexes: [
        {
          name: "user_tokens_pkey",
          unique: true,
          fields: [
            { name: "id" },
          ]
        },
      ]
    }
  );
  return UserTokens;
};
