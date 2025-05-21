#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from datetime import datetime
from pydantic import ConfigDict, EmailStr, Field

from backend.common.enums import StatusType
from backend.common.schema import SchemaBase, CustomPhoneNumber

# Re-define AuthLoginParam for LDAP, potentially without captcha if LDAP handles that
class LDAPAuthLoginParam(SchemaBase):
    """LDAP 用户登录参数"""
    username: str = Field(description='用户名')
    password: str = Field(description='密码')
    # Captcha might not be needed if LDAP server handles auth attempts directly
    # captcha: str = Field(description='验证码')


# Schemas for LDAPUser based on LDAPUser model
class LDAPUserInfoBase(SchemaBase):
    """LDAP用户信息基础模型"""
    username: str = Field(description='用户名')
    nickname: str = Field(description='昵称')
    email: EmailStr = Field(examples=['user@example.com'], description='邮箱')
    phone: CustomPhoneNumber | None = Field(None, description='手机号')
    avatar: str | None = Field(None, description='头像')
    ldap_dn: str | None = Field(None, description='LDAP Distinguished Name')


class LDAPUserCreate(LDAPUserInfoBase):
    """创建LDAP用户参数"""
    # For LDAP, password might be set on the LDAP server, not locally.
    # If creating a local representation, password might not be needed here.
    # password: str | None = Field(None, description='密码 (if stored locally)')
    pass


class LDAPUserUpdate(LDAPUserInfoBase):
    """更新LDAP用户参数"""
    # Similar to create, password update might be an LDAP server operation.
    # status: StatusType | None = Field(None, description='用户账号状态(0停用 1正常)')
    # is_superuser: bool | None = Field(None, description='超级权限(0否 1是)')
    # is_staff: bool | None = Field(None, description='后台管理登陆(0否 1是)')
    pass


class LDAPUserInDB(LDAPUserInfoBase):
    """LDAP用户信息详情 (from DB)"""
    model_config = ConfigDict(from_attributes=True)

    id: int = Field(description='用户 ID')
    uuid: str = Field(description='用户 UUID')
    status: StatusType = Field(StatusType.enable, description='状态')
    is_superuser: bool = Field(description='是否超级管理员')
    is_staff: bool = Field(description='是否管理员')
    is_multi_login: bool = Field(description='是否允许多端登录') # Consider if relevant for LDAP
    join_time: datetime = Field(description='加入时间')
    last_login_time: datetime | None = Field(None, description='最后登录时间')

# For now, GetLoginToken and GetSwaggerToken will still be imported from backend.app.admin.schema.token
# in ldap_auth.py. If they need customization (e.g., different user schema),
# they would be redefined here.

# Example of how GetSwaggerToken could be redefined if LDAPUserInDB was used instead of GetUserInfoDetail
# from backend.app.admin.schema.user import GetUserInfoDetail # Keep for now if GetSwaggerToken not redefined

# class GetLDAPSwaggerToken(SchemaBase):
#     """Swagger 认证令牌 for LDAP"""
#     access_token: str = Field(description='访问令牌')
#     token_type: str = Field('Bearer', description='令牌类型')
#     user: LDAPUserInDB = Field(description='LDAP 用户信息') # Changed to LDAPUserInDB

# class GetLDAPLoginToken(AccessTokenBase): # Assuming AccessTokenBase is generic enough
#     """获取登录令牌 for LDAP"""
#     user: LDAPUserInDB = Field(description='LDAP 用户信息') # Changed to LDAPUserInDB
