#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pytest
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.plugin.ldap.ldap_auth import router as ldap_router # Updated path
from backend.plugin.ldap.service import LDAPAuthService, ldap_auth_service as actual_ldap_service # Updated path
from backend.plugin.ldap.schema import LDAPAuthLoginParam, LDAPUserInDB # Updated path
from backend.app.admin.schema.token import GetLoginToken, GetSwaggerToken
from backend.common.response.response_schema import response_base # For success wrapping

# Create a minimal FastAPI app for testing this router
from starlette.responses import JSONResponse
from backend.common.exception.errors import AuthorizationError
from fastapi.security import HTTPBasicCredentials # Import for dependency override

app = FastAPI()

# Define and apply dependency override for HTTPBasicCredentials
async def override_basic_credentials():
    return HTTPBasicCredentials(username="testuser", password="testpassword") # Dummy creds

app.dependency_overrides[HTTPBasicCredentials] = override_basic_credentials

# Add an exception handler for AuthorizationError for the test app
@app.exception_handler(AuthorizationError)
async def authorization_exception_handler(request, exc: AuthorizationError):
    return JSONResponse(
        status_code=exc.code, # Typically 401
        content={"code": exc.code, "msg": exc.msg, "data": None},
    )

# Add a generic HTTPException handler
from fastapi import HTTPException

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}, # Standard FastAPI way
    )

app.include_router(ldap_router, prefix="/ldap")

# Replace the actual service instance with a mock for the duration of tests
mock_ldap_service = AsyncMock(spec=LDAPAuthService)

def override_ldap_service():
    return mock_ldap_service

# Apply the override to the dependency used in the router
# This depends on how the service is injected. If it's a global instance, we might need to patch it directly.
# Assuming ldap_auth.py imports `ldap_auth_service` from service.py and uses it directly.
# We will patch the instance in the ldap_auth module.

@pytest.fixture(autouse=True)
def patch_ldap_service_instance():
    with patch('backend.plugin.ldap.ldap_auth.ldap_auth_service', new=mock_ldap_service) as _fixture_mock: # Updated patch path
        # Reset the mock before each test
        _fixture_mock.reset_mock()
        yield _fixture_mock


client = TestClient(app)

# Test data
test_ldap_user_in_db = LDAPUserInDB(
    id=1,
    uuid="test-uuid",
    username="testuser",
    nickname="Test User",
    email="test@example.com",
    status=1,
    is_superuser=False,
    is_staff=False,
    is_multi_login=False,
    join_time="2024-01-01T12:00:00Z", # Using ISO format string
    last_login_time=None,
    ldap_dn="cn=testuser,dc=example,dc=com"
)

test_login_token = GetLoginToken(
    access_token="test_access_token",
    access_token_expire_time="2024-01-01T13:00:00Z", # Using ISO format string
    session_uuid="test_session_uuid",
    user=test_ldap_user_in_db 
)

test_swagger_token = GetSwaggerToken(
    access_token="test_swagger_access_token",
    token_type="Bearer",
    user=test_ldap_user_in_db 
)

# More specific user detail for swagger tests to match GetUserInfoDetail
from backend.app.admin.schema.user import GetUserInfoDetail
from backend.common.enums import StatusType

mock_user_for_swagger = GetUserInfoDetail(
    id=1,
    uuid="test-uuid",
    username="testuser",
    nickname="Test User",
    email="test@example.com",
    status=StatusType.enable,
    is_superuser=False,
    is_staff=False,
    is_multi_login=False,
    join_time="2024-01-01T12:00:00Z",
    last_login_time=None,
    avatar=None,
    phone=None,
    dept_id=None 
)

class TestLDAPAuthEndpoints:

    def test_ldap_login_success(self):
        mock_ldap_service.ldap_login = AsyncMock(return_value=test_login_token)
        
        login_data = LDAPAuthLoginParam(username="testuser", password="password")
        
        response = client.post("/ldap/ldap_login", json=login_data.model_dump())
        
        assert response.status_code == 200
        # Assuming your response_base.success wraps the data
        response_json = response.json()
        assert response_json["code"] == 200
        assert response_json["msg"] == "请求成功" # Updated to actual message
        # Deep compare the 'data' part with the expected token structure
        # Need to handle datetime string formats if they are not exact
        assert response_json["data"]["access_token"] == test_login_token.access_token
        assert response_json["data"]["user"]["username"] == test_login_token.user.username
        
        mock_ldap_service.ldap_login.assert_called_once()
        # More detailed argument checking can be added here if needed

    def test_ldap_login_failure(self):
        # Simulate AuthorizationError from service
        from backend.common.exception.errors import AuthorizationError
        mock_ldap_service.ldap_login = AsyncMock(side_effect=AuthorizationError(msg="Incorrect username or password"))
        
        login_data = LDAPAuthLoginParam(username="wronguser", password="wrongpassword")
        
        response = client.post("/ldap/ldap_login", json=login_data.model_dump())
        
        assert response.status_code == 401 # Based on how AuthorizationError is handled by FastAPI/custom handlers
        response_json = response.json()
        assert response_json["code"] == 401 # Or whatever your error handler returns
        assert "Incorrect username or password" in response_json["msg"]
        
        mock_ldap_service.ldap_login.assert_called_once()

    def test_swagger_ldap_login_success(self):
        # The service returns (token_string, user_object)
        # Mock to return the GetUserInfoDetail compatible object
        mock_ldap_service.swagger_ldap_login = AsyncMock(return_value=("test_swagger_access_token", mock_user_for_swagger))
        
        response = client.post("/ldap/login/ldap_swagger", auth=("testuser", "password"))
        
        assert response.status_code == 200
        response_json = response.json()
        # GetSwaggerToken is returned directly, not wrapped by response_base
        assert response_json["access_token"] == "test_swagger_access_token"
        assert response_json["token_type"] == "Bearer"
        assert response_json["user"]["username"] == mock_user_for_swagger.username # Compare with the correct mock user data
        
        mock_ldap_service.swagger_ldap_login.assert_called_once()

    def test_swagger_ldap_login_failure(self):
        from fastapi import HTTPException
        # Simulate HTTPException from service for swagger
        mock_ldap_service.swagger_ldap_login = AsyncMock(
            side_effect=HTTPException(status_code=401, detail="Incorrect username or password")
        )
        
        response = client.post("/ldap/login/ldap_swagger", auth=("wronguser", "wrongpassword"))
        
        # Check if the mock was called, to ensure the error isn't from the dependency itself
        # This assertion should now pass as the dependency override should allow the endpoint to be called.
        mock_ldap_service.swagger_ldap_login.assert_called_once() 

        assert response.status_code == 401
        response_json = response.json()
        assert "Incorrect username or password" in response_json["detail"] # HTTPException uses 'detail'

# To run these tests, you would typically use pytest:
# Ensure conftest.py is set up if needed for more complex app setups or fixtures.
# For this isolated test, direct TestClient usage with a minimal app should work.
# Example: pytest backend/app/plugin/ldap/tests/test_ldap_auth.py

# Note on datetimes:
# Pydantic models might serialize datetimes to strings. When comparing, ensure format consistency
# or parse strings back to datetime objects for comparison if precision is critical.
# For these tests, we are primarily checking token strings and key user identifiers.
# The provided test_login_token and test_ldap_user_in_db use strings for datetimes
# to simplify matching with JSON responses.
# If the actual service returns datetime objects, those will be serialized to ISO strings in JSON.
# The GetLoginToken and GetSwaggerToken in the actual application might have datetime objects.
# For the purpose of these tests, we've defined their test counterparts with string datetimes.
# This might need adjustment if the actual schema serialization is different.
# For example, if `join_time` in LDAPUserInDB is a datetime object, model_validate will handle it.
# When it's part of GetLoginToken.user, it will be serialized to string in the final JSON.
# The test data `test_ldap_user_in_db` has `join_time` as a string to match this.
# `test_login_token` also has `access_token_expire_time` as a string.
# This should align with how FastAPI/Pydantic serialize datetime fields in JSON responses.
# If the schemas expect actual datetime objects and perform validation, ensure test data respects that.
# For now, the schemas (LDAPUserInDB, GetLoginToken) are assumed to handle string representations
# or are defined with string types for these fields where they appear in responses.
# A quick check on the actual schemas:
# - GetUserInfoDetail (basis for user in GetLoginToken/GetSwaggerToken) has join_time: datetime
# - GetLoginToken has access_token_expire_time: datetime
# This means the actual response will serialize these to ISO strings.
# Our test data (test_ldap_user_in_db, test_login_token) using strings for these fields is correct for matching JSON.
# The Pydantic models like LDAPUserInDB will parse these strings into datetime objects if the field type is `datetime`.
# Example: LDAPUserInDB(..., join_time="2024-01-01T12:00:00Z") will parse the string to a datetime object.
# When this LDAPUserInDB instance is part of a response (e.g., inside GetLoginToken), its datetime fields
# will be serialized back to ISO strings. So, the string-based comparison in tests is appropriate.
# One minor adjustment: `test_ldap_user_in_db.join_time` should be a valid ISO string that Pydantic can parse if LDAPUserInDB expects datetime.
# The current string "2024-01-01T12:00:00Z" is a valid ISO 8601 string.
# Similarly for `test_login_token.access_token_expire_time`.
# The `AuthLoginParam` model in the `ldap_auth.py` uses `obj: LDAPAuthLoginParam`.
# LDAPAuthLoginParam has username: str, password: str. So, `login_data.model_dump()` is correct.
# The `swagger_ldap_login` endpoint uses `obj: Annotated[HTTPBasicCredentials, Depends()]`.
# TestClient's `auth` parameter handles this correctly.
# `response_base.success(data=data)` is used in `ldap_login`. The tests account for this structure.
# `swagger_ldap_login` returns `GetSwaggerToken` directly. The tests account for this.
# The mocking strategy using `patch` on the imported service instance in `ldap_auth.py` is standard.
# `autouse=True` and `reset_mock()` ensure mock isolation between tests.
# `AsyncMock` is correctly used for async service methods.
# Error handling for AuthorizationError (custom) and HTTPException (FastAPI) is tested.
# The test data for schemas seems fine for JSON comparison.
# `LDAPUserInDB.model_validate(ldap_user_model)` is used in service.py, so test data should be valid.
# `GetLoginToken(user=user_info_for_token)` where user_info_for_token is LDAPUserInDB.
# This means GetLoginToken's `user` field (typed as GetUserInfoDetail) must be compatible with LDAPUserInDB.
# For testing, this is okay as we control the mock. In reality, ensure fields match or map.
# `GetSwaggerToken` also has `user: GetUserInfoDetail`. Same consideration.
# Our test_ldap_user_in_db is an instance of LDAPUserInDB. It is assigned to `user` in test_login_token and test_swagger_token.
# This is fine for mocking, as the mock service returns these pre-constructed objects.
# The actual service would ensure compatibility.
# If GetUserInfoDetail has fields not in LDAPUserInDB, it could cause issues in real app, but not in these tests.
# For now, LDAPUserInDB has most common fields.
# `id` in `LDAPUserInDB` is `int`, `uuid` is `str`. This matches `GetUserInfoDetail`.
# `join_time` is `datetime` in `GetUserInfoDetail`, `LDAPUserInDB` schema definition should match for validation.
# If `LDAPUserInDB` has `join_time: datetime`, then `LDAPUserInDB(..., join_time="ISO_STRING")` is fine.
# The current `LDAPUserInDB` in `schema.py` has `join_time: datetime`. So this is okay.
# Final check on response structure for `ldap_login`:
# It returns ResponseSchemaModel[GetLoginToken]. ResponseSchemaModel wraps with code, msg, data.
# `response_base.success(data=data)` creates this. Test `test_ldap_login_success` handles this.
# All looks reasonable for testing the API endpoints with mocked service.
# I have already created `backend/app/plugin/ldap/tests/__init__.py` and `backend/app/plugin/ldap/tests/test_ldap_auth.py` with the initial set of tests in the previous turn.
#
# The tests in `backend/app/plugin/ldap/tests/test_ldap_auth.py` cover:
# 1.  Successful LDAP login (`/ldap/ldap_login`).
# 2.  Failed LDAP login (authorization error).
# 3.  Successful Swagger LDAP login (`/ldap/login/ldap_swagger`).
# 4.  Failed Swagger LDAP login (HTTP exception).
#
# These tests use `fastapi.testclient.TestClient` and mock the `LDAPAuthService` using `unittest.mock.AsyncMock` and `unittest.mock.patch` to isolate the router logic and control the behavior of the service during tests. The response status codes and basic structure of the JSON response (including wrapped success responses and error messages) are asserted. Test data for schemas like `LDAPUserInDB`, `GetLoginToken`, and `GetSwaggerToken` has been defined.
#
# The focus was on testing API endpoints with mocked services as requested. Optional testing for service methods and CRUD operations are not included in this step, aligning with the subtask's primary focus.
#
# I will now submit the subtask report.
