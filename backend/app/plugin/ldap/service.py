#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Any

from fastapi import Request, Response, HTTPException, status
from fastapi.security import HTTPBasicCredentials
from starlette.background import BackgroundTasks

from backend.app.admin.schema.token import GetLoginToken, GetSwaggerToken # Use existing schemas for now
from backend.app.plugin.ldap.schema import LDAPAuthLoginParam, LDAPUserInDB # Use LDAP specific schemas
from backend.app.plugin.ldap.crud import crud_ldap_user # Placeholder CRUD
from backend.app.plugin.ldap.model import LDAPUser # LDAP User model

from backend.common.security.jwt import create_access_token, create_refresh_token
from backend.core.conf import settings
from backend.database.db import async_db_session
# from backend.database.redis import redis_client # Will be needed for full login flow
from backend.common.exception import errors
from backend.utils.timezone import timezone


class LDAPAuthService:
    async def _placeholder_ldap_verify(self, username: str, password: str) -> tuple[bool, str | None, str | None, str | None]:
        """
        Placeholder for actual LDAP verification.
        Returns: (success, email, nickname, ldap_dn)
        """
        # In a real scenario, this would connect to LDAP and verify credentials.
        # For now, accept any username if password is "password"
        if password == "password": # Dummy check
            print(f"LDAPAuthService: Placeholder LDAP verification successful for user: {username}")
            # Simulate fetching some details from LDAP
            return True, f"{username}@example.com", username.capitalize(), f"cn={username},dc=example,dc=com"
        print(f"LDAPAuthService: Placeholder LDAP verification failed for user: {username}")
        return False, None, None, None

    async def swagger_ldap_login(self, obj: HTTPBasicCredentials) -> tuple[str, LDAPUserInDB]:
        """
        Simulates LDAP authentication for Swagger.
        """
        ldap_success, email, nickname, ldap_dn = await self._placeholder_ldap_verify(obj.username, obj.password)

        if not ldap_success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"},
            )

        async with async_db_session.begin() as db:
            # Use placeholder CRUD to get or create user
            # In a real app, you might sync more details from LDAP here
            ldap_user_model = await crud_ldap_user.get_or_create_user(
                db=db, username=obj.username, email=email, ldap_dn=ldap_dn
            )
            # Ensure nickname from LDAP is used if available, otherwise fallback
            if nickname:
                ldap_user_model.nickname = nickname
            # db.add(ldap_user_model) # crud_ldap_user.get_or_create_user might handle this
            # await db.commit()
            await db.refresh(ldap_user_model)


            # Create Pydantic model from SQLAlchemy model for the response
            # For GetSwaggerToken, it expects a user object that matches GetUserInfoDetail structure.
            # We'll create an LDAPUserInDB object and then map it if necessary,
            # or adjust GetSwaggerToken to accept LDAPUserInDB if that's the long-term plan.
            # For now, let's assume GetSwaggerToken's 'user' field can take any object
            # that has the necessary attributes. A proper solution would be to have a
            # GetLDAPSwaggerToken schema or ensure LDAPUserInDB is compatible.

            # For simplicity, let's assume LDAPUserInDB is compatible enough or GetSwaggerToken is flexible.
            user_info_for_token = LDAPUserInDB.model_validate(ldap_user_model)


        # Generate JWT token (simplified from auth_service)
        # The swagger token typically doesn't need multi_login checks or extensive claims
        access_token_payload = {
            "sub": str(ldap_user_model.id), # Use user's actual ID from DB
            "username": ldap_user_model.username,
            "user_type": "ldap_swagger", # Custom claim for LDAP swagger
            "is_superuser": ldap_user_model.is_superuser,
            "is_staff": ldap_user_model.is_staff,
        }
        # Note: create_access_token from common.security.jwt expects user_id and multi_login status.
        # We are creating a more direct token here for simplicity for swagger.
        # For a more consistent approach, adapt create_access_token or use it as is if appropriate.
        
        # Re-using existing create_access_token for consistency:
        # This requires ldap_user_model to have an `id` and `is_multi_login` attribute.
        # Our LDAPUser model has `id`. `is_multi_login` defaults to False.
        token_info = await create_access_token(
            user_id=str(ldap_user_model.id),
            multi_login=ldap_user_model.is_multi_login, # from LDAPUser model
            # extra info for swagger (can be minimal)
            swagger=True,
            username=ldap_user_model.username
        )
        # The user object returned by GetSwaggerToken is GetUserInfoDetail.
        # We need to ensure the user_info_for_token is compatible or transform it.
        # For now, we pass it directly. This might need adjustment.
        return token_info.access_token, user_info_for_token


    async def ldap_login(self, request: Request, response: Response, obj: LDAPAuthLoginParam, background_tasks: BackgroundTasks) -> GetLoginToken:
        """
        Handles actual LDAP authentication.
        """
        ldap_success, email, nickname, ldap_dn = await self._placeholder_ldap_verify(obj.username, obj.password)

        if not ldap_success:
            # In a real app, log this attempt, handle specific LDAP errors, etc.
            # task = BackgroundTask(...) # For login log
            # background_tasks.add_task(task)
            raise errors.AuthorizationError(msg="Incorrect username or password") # Using custom error

        async with async_db_session.begin() as db:
            # Get or create user
            ldap_user_model = await crud_ldap_user.get_or_create_user(
                db=db, username=obj.username, email=email, ldap_dn=ldap_dn
            )
            if nickname:
                ldap_user_model.nickname = nickname
            
            # Simulate updating last login time (normally done by a DAO method)
            ldap_user_model.last_login_time = timezone.now()
            # db.add(ldap_user_model) # crud_ldap_user.get_or_create_user might handle this
            # await db.commit()
            await db.refresh(ldap_user_model)

            user_info_for_token = LDAPUserInDB.model_validate(ldap_user_model)

        # Generate JWT and refresh tokens (reusing logic from auth_service)
        # This assumes ldap_user_model has id, is_multi_login, username, nickname, last_login_time
        a_token = await create_access_token(
            user_id=str(ldap_user_model.id),
            multi_login=ldap_user_model.is_multi_login,
            username=ldap_user_model.username,
            nickname=user_info_for_token.nickname, # from pydantic model for consistency
            last_login_time=timezone.t_str(ldap_user_model.last_login_time) if ldap_user_model.last_login_time else None,
            ip=request.state.ip,
            os=request.state.os,
            browser=request.state.browser,
            device=request.state.device,
        )
        r_token = await create_refresh_token(
            user_id=str(ldap_user_model.id),
            multi_login=ldap_user_model.is_multi_login
        )

        # Set cookies for tokens (similar to auth_service)
        response.set_cookie(
            key=settings.COOKIE_REFRESH_TOKEN_KEY,
            value=r_token.refresh_token,
            max_age=settings.COOKIE_REFRESH_TOKEN_EXPIRE_SECONDS,
            expires=timezone.f_utc(r_token.refresh_token_expire_time), # Ensure this is UTC datetime
            httponly=True,
            samesite=settings.COOKIE_SAMESITE,
            secure=settings.COOKIE_SECURE,
        )
        
        # Store tokens in Redis (placeholder - actual redis_client calls would be here)
        # await redis_client.setex(f'{settings.TOKEN_REDIS_PREFIX}:{ldap_user_model.id}:{a_token.session_uuid}', settings.TOKEN_EXPIRE_SECONDS, a_token.access_token)
        # await redis_client.setex(f'{settings.TOKEN_REFRESH_REDIS_PREFIX}:{ldap_user_model.id}:{r_token.refresh_token_session_uuid}', settings.REFRESH_TOKEN_EXPIRE_SECONDS, r_token.refresh_token)
        print(f"LDAPAuthService: Tokens would be stored in Redis for user {ldap_user_model.username}")


        # Log successful login (placeholder - actual login_log_service call)
        # background_tasks.add_task(login_log_service.create, ...)
        print(f"LDAPAuthService: Login successful for user {ldap_user_model.username}, background tasks would run.")

        # The GetLoginToken schema expects a 'user' field of type GetUserInfoDetail.
        # We need to ensure user_info_for_token is compatible.
        # For now, passing directly. This might require adjustment or a GetLDAPLoginToken schema.
        return GetLoginToken(
            access_token=a_token.access_token,
            access_token_expire_time=a_token.access_token_expire_time,
            session_uuid=a_token.session_uuid,
            user=user_info_for_token, # This should be compatible with GetUserInfoDetail
        )

ldap_auth_service = LDAPAuthService()
