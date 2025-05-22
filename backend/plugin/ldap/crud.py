#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy_crud_plus import CRUDPlus

from backend.plugin.ldap.model import LDAPUser # Updated path
from backend.plugin.ldap.schema import LDAPUserCreate, LDAPUserUpdate # Updated path
from backend.database.db import uuid4_str # For default uuid if needed
from backend.utils.timezone import timezone # For default join_time if needed

class CRUDLDAPUser(CRUDPlus[LDAPUser]):
    async def get_or_create_user(
        self,
        db: AsyncSession,
        username: str,
        email: str | None = None,
        ldap_dn: str | None = None,
        nickname: str | None = None
    ) -> LDAPUser:
        """
        Get an existing LDAPUser or create a new one.
        Tries to find a user by username, then by ldap_dn if provided.
        """
        stmt = select(self.model).where(self.model.username == username)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if user:
            # Optionally update user's details if they differ, e.g., email or ldap_dn
            if email and user.email != email:
                user.email = email
            if ldap_dn and user.ldap_dn != ldap_dn:
                user.ldap_dn = ldap_dn
            if nickname and user.nickname != nickname: # Added nickname update
                user.nickname = nickname
            if email or ldap_dn or nickname:
                db.add(user)
                await db.flush()
                await db.refresh(user)
            return user

        if ldap_dn: # If not found by username, try by ldap_dn as it should be unique
            stmt_dn = select(self.model).where(self.model.ldap_dn == ldap_dn)
            result_dn = await db.execute(stmt_dn)
            user_by_dn = result_dn.scalar_one_or_none()
            if user_by_dn:
                # User found by DN, potentially update username if it was different
                if user_by_dn.username != username:
                    # This case might need careful handling depending on policy
                    # For now, let's assume we update username if found by DN
                    user_by_dn.username = username
                if email and user_by_dn.email != email:
                    user_by_dn.email = email
                if nickname and user_by_dn.nickname != nickname: # Added nickname update
                    user_by_dn.nickname = nickname
                db.add(user_by_dn)
                await db.flush()
                await db.refresh(user_by_dn)
                return user_by_dn
        
        # If user does not exist by username or ldap_dn, create a new one
        new_user_data = {
            "username": username,
            "email": email or f"{username}@example.com", # Default email if not provided
            "nickname": nickname or username.capitalize(), # Default nickname
            "ldap_dn": ldap_dn,
            "uuid": uuid4_str(),
            "join_time": timezone.now(),
            "status": 1, # Default status, e.g., active
            "is_superuser": False,
            "is_staff": False, # Or True, depending on default for LDAP users
            "is_multi_login": False,
            # password and salt are intentionally omitted for LDAP users unless local fallback is desired
        }
        # Ensure we don't pass None to fields that don't allow it if defaults aren't set in model
        create_schema = LDAPUserCreate(**new_user_data) # Validate with schema before model creation
        
        db_obj = self.model(**create_schema.model_dump(exclude_unset=True))
        db.add(db_obj)
        await db.flush() # Use flush to get ID before commit if needed, or if commit is handled outside
        await db.refresh(db_obj)
        return db_obj

    async def get_by_username(self, db: AsyncSession, username: str) -> LDAPUser | None:
        """
        Get a user by username.
        """
        stmt = select(self.model).where(self.model.username == username)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    # Other standard CRUD methods (basic implementation from CRUDPlus or custom if needed)
    # CRUDPlus provides get, create, update, delete out of the box.
    # We can override them if specific logic is needed beyond what LDAPUserCreate/Update provide.

    # Example of overriding create if more specific logic than CRUDPlus default is needed
    async def create(self, db: AsyncSession, obj_in: LDAPUserCreate, **kwargs: Any) -> LDAPUser:
        """
        Create a new LDAP user.
        This overrides the default CRUDPlus create if specific pre-processing is needed.
        """
        # Add default values if not provided and not handled by model defaults
        # For example, uuid, join_time etc.
        # However, these are best handled by model default_factory or schema default_factory
        
        # Convert Pydantic schema to dictionary
        create_data = obj_in.model_dump(exclude_unset=True)
        
        # Add any specific logic before creating
        if 'uuid' not in create_data:
             create_data['uuid'] = uuid4_str()
        if 'join_time' not in create_data:
             create_data['join_time'] = timezone.now()
        if 'status' not in create_data:
            create_data['status'] = 1 # Default active

        return await super().create(db, create_data, **kwargs)

    # get, update, delete can use CRUDPlus defaults if LDAPUserUpdate schema is appropriate
    # async def get(self, db: AsyncSession, id: Any) -> LDAPUser | None:
    # return await super().get(db, id)

    # async def update(self, db: AsyncSession, *, db_obj: LDAPUser, obj_in: LDAPUserUpdate) -> LDAPUser:
    # return await super().update(db, db_obj=db_obj, obj_in=obj_in)
    
    # async def delete(self, db: AsyncSession, id: Any) -> LDAPUser | None:
    # return await super().delete(db, id)

crud_ldap_user = CRUDLDAPUser(LDAPUser)
