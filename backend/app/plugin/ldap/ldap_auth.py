#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from fastapi.security import HTTPBasicCredentials

from starlette.background import BackgroundTasks

from backend.app.admin.schema.token import GetLoginToken, GetSwaggerToken
# Import LDAPAuthLoginParam from the new location
from backend.app.plugin.ldap.schema import LDAPAuthLoginParam
# Remove old auth_service import
from backend.app.plugin.ldap.service import ldap_auth_service # Import new LDAPAuthService instance
from backend.common.response.response_schema import ResponseSchemaModel, response_base


router = APIRouter()

@router.post('/login/ldap_swagger', summary='swagger 调试专用', description='用于快捷获取 token 进行 ldap_swagger 认证')
async def swagger_ldap_login(obj: Annotated[HTTPBasicCredentials, Depends()]) -> GetSwaggerToken:
    token, user = await ldap_auth_service.swagger_ldap_login(obj=obj) # Use ldap_auth_service
    return GetSwaggerToken(access_token=token, user=user)

@router.post('/ldap_login', summary='LDAP登录', description='使用LDAP账号和密码登录系统')
async def ldap_login(
    request: Request, response: Response, obj: LDAPAuthLoginParam, background_tasks: BackgroundTasks # Use LDAPAuthLoginParam
) -> ResponseSchemaModel[GetLoginToken]:
    data = await ldap_auth_service.ldap_login(request=request, response=response, obj=obj, background_tasks=background_tasks) # Use ldap_auth_service
    return response_base.success(data=data)
