#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime

from sqlalchemy import VARBINARY, Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import BYTEA, INTEGER
from sqlalchemy.orm import Mapped, mapped_column

from backend.common.model import Base, id_key
from backend.database.db import uuid4_str
from backend.utils.timezone import timezone

class LDAPUser(Base):
    """LDAP 用户表"""

    __tablename__ = 'sys_ldap_user' # Changed table name for clarity

    id: Mapped[id_key] = mapped_column(init=False)
    uuid: Mapped[str] = mapped_column(String(50), init=False, default_factory=uuid4_str, unique=True)
    username: Mapped[str] = mapped_column(String(20), unique=True, index=True, comment='用户名')
    nickname: Mapped[str] = mapped_column(String(20), unique=True, comment='昵称')
    # LDAP users typically authenticate against LDAP, so a local password might not be needed
    # or might be handled differently. For now, let's keep it, but it's a point for consideration.
    password: Mapped[str | None] = mapped_column(String(255), comment='密码 (if stored locally)')
    salt: Mapped[bytes | None] = mapped_column(VARBINARY(255).with_variant(BYTEA(255), 'postgresql'), comment='加密盐 (if stored locally)')
    email: Mapped[str] = mapped_column(String(50), unique=True, index=True, comment='邮箱')
    ldap_dn: Mapped[str | None] = mapped_column(String(255), unique=True, comment='LDAP Distinguished Name') # Moved Up
    is_superuser: Mapped[bool] = mapped_column(
        Boolean().with_variant(INTEGER, 'postgresql'), default=False, comment='超级权限(0否 1是)'
    )
    is_staff: Mapped[bool] = mapped_column(
        Boolean().with_variant(INTEGER, 'postgresql'), default=False, comment='后台管理登陆(0否 1是)'
    )
    status: Mapped[int] = mapped_column(default=1, index=True, comment='用户账号状态(0停用 1正常)')
    # is_multi_login might not be relevant if auth is purely via LDAP sessions
    is_multi_login: Mapped[bool] = mapped_column(
        Boolean().with_variant(INTEGER, 'postgresql'), default=False, comment='是否重复登陆(0否 1是)'
    )
    avatar: Mapped[str | None] = mapped_column(String(255), default=None, comment='头像')
    phone: Mapped[str | None] = mapped_column(String(11), default=None, comment='手机号')
    join_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), init=False, default_factory=timezone.now, comment='加入时间 (when synced to local DB)'
    )
    last_login_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), init=False, onupdate=timezone.now, comment='上次登录 (if tracked locally)'
    )
    # Removed relationships: dept, socials, roles
    # Additional LDAP specific fields can be added here if needed, e.g., distinguishedName (dn)
