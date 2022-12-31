"use strict";
const { Model } = require("sequelize");

export interface SystemRoleAttributes {
  id: number;
  role_name: string;
  access_level: number;
  insert_date: Date;
  update_date?: Date;
}

module.exports = (sequelize: any, DataTypes: any) => {
  class SystemRole
    extends Model<SystemRoleAttributes>
    implements SystemRoleAttributes
  {
    id!: number;
    role_name!: string;
    access_level!: number;
    insert_date!: Date;
    update_date?: Date;

    static associate(models: any) {
      // define association here
      // console.log(models)
    }
  }

  SystemRole.init(
    {
      id: {
        autoIncrement: true,
        type: DataTypes.INTEGER,
        allowNull: false,
        primaryKey: true,
      },
      role_name: {
        type: DataTypes.STRING(100),
        allowNull: false,
      },
      access_level: {
        type: DataTypes.INTEGER,
        allowNull: false,
      },
      insert_date: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      update_date: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      sequelize,
      tableName: "system_role",
      schema: "public",
      timestamps: true,
      createdAt: 'insert_date',
      updatedAt: 'update_date',
      indexes: [
        {
          name: "system_role_pkey",
          unique: true,
          fields: [{ name: "id" }],
        },
      ],
    }
  );
  return SystemRole;
};
