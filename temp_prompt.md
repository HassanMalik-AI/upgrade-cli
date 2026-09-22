<USER_REQUEST>
# 🎯 **Complete Fix Prompt for Phase 2 & Phase 3 Issues**

Copy this prompt and use it to fix all issues professionally:

---

## 📋 **PROMPT: Fix All Phase 2 & Phase 3 Issues**

```
I have a FastAPI project with issues found in Phase 2 (Repositories & Services) 
and Phase 3 (Services Layer) reviews. Please provide complete, production-ready 
fixes for each issue with line-by-line explanations.

═══════════════════════════════════════════════════════════════
PHASE 2 ISSUES (Repository & Service Layer)
═══════════════════════════════════════════════════════════════

ISSUE P2-1: Token Hashing in Wrong Location
────────────────────────────────────────────
PROBLEM:
- `hash_refresh_token()` and `generate_raw_refresh_token()` are in 
  `services/auth_service.py`
- These are security primitives, not business logic
- Not reusable across layers

REQUIRED FIX:
- Create new file: `app/core/security/tokens.py`
- Move both functions there with:
  * Complete docstrings
  * Type hints
  * Security notes
  * Constants for token length
- Update imports in `services/auth_service.py`
- Update any other files using these functions
- Add `__all__` exports

DELIVERABLE:
1. New file: `app/core/security/tokens.py` (complete)
2. Updated: `services/auth_service.py` (imports only)
3. Verification: grep for old imports


ISSUE P2-2: Sync Functions in email_service.py
──────────────────────────────────────────────
PROBLEM:
- Module-level functions `send_email()`, `send_verification_email()`, 
  `send_reset_email()` are SYNC (blocking)
- They block the event loop when called from async code
- The `EmailService` class already has proper async methods

REQUIRED FIX:
- Option A (Recommended): Remove sync functions entirely
- Option B: Mark them with `@deprecated` decorator and raise warnings
- Option C: Convert them to async wrappers calling EmailService

Choose Option A or B. Provide:
1. Updated `services/email_service.py`
2. Add deprecation warnings if Option B
3. Remove `__all__` entries for sync functions if Option A


ISSUE P2-3: Email URL Building Missing api_prefix
──────────────────────────────────────────────────
PROBLEM:
- Sync functions in email_service.py build URLs like:
  `f"{settings.base_url}/auth/verify?token={token}"`
- Missing `api_prefix` (should be `/api/v1`)
- Inconsistent with async `_build_url()` method

REQUIRED FIX:
- If keeping sync functions, use consistent `_build_url()` logic
- Include `api_prefix` in all URLs
- Add tests/verification examples

DELIVERABLE:
1. Updated email URL building (sync or removed)
2. Example URLs showing correct format


ISSUE P2-4: Email Module Deprecation Strategy
──────────────────────────────────────────────
PROBLEM:
- Sync email functions may still be called
- No clear migration path

REQUIRED FIX:
- Add clear deprecation warnings
- Document migration path
- OR remove entirely with clear error messages

DELIVERABLE:
1. Deprecation decorator or removal
2. Migration guide in docstring


═══════════════════════════════════════════════════════════════
PHASE 3 ISSUES (Service Layer)
═══════════════════════════════════════════════════════════════

ISSUE P3-1: BaseService Not Used (CRITICAL)
─────────────────────────────────────────────
PROBLEM:
- `services/base/base_service.py` exists with:
  * get() method
  * get_or_404() method
  * commit(), rollback(), flush()
  * exists() method
  * log_operation() method
- BUT no service inherits from it:
  * UserService ❌
  * AuthService ❌
  * ProductService ❌
  * TotpService ❌
  * EmailService ❌ (stateless — OK)
  * SocialAuthService ❌ (stateless — OK)

REQUIRED FIX:
Choose ONE strategy:

Option A (Recommended): Make services inherit
  - UserService(BaseService[User])
  - ProductService(BaseService[Product])
  - TotpService(BaseService[TotpSecret])
  - AuthService does NOT inherit (orchestrator, not entity service)
  - EmailService does NOT inherit (stateless)
  - SocialAuthService does NOT inherit (stateless)

Option B: Remove BaseService entirely
  - Delete `services/base/base_service.py`
  - Update `services/base/__init__.py`
  - No inheritance needed

Option C: Use composition
  - Services hold `self.base = BaseService(...)`
  - Delegate common operations

Provide the CHOSEN option with:
1. Updated service files
2. Explanation of why this option
3. Impact on existing code
4. Testing verification


ISSUE P3-2: AuthService Bypasses TotpService (CRITICAL)
────────────────────────────────────────────────────────
PROBLEM:
- AuthService directly uses TotpSecretRepository:
  * `self.totp = TotpSecretRepository(session)`
  * `self.totp.has_active_2fa(user_id)`
  * `self.totp.get_by_user_id(user_id)`
  * Duplicates logic that's in TotpService
- Violates layering: Service → Service, not Service → Repository
- Lockout rules duplicated

REQUIRED FIX:
- AuthService should use TotpService:
  * `self.totp_service = TotpService(session)`
  * Replace direct repo calls with service methods
- Remove `_verify_2fa` method (use TotpService.verify_login)
- Remove `_has_2fa_enabled` (use TotpService.is_enabled)

DELIVERABLE:
1. Updated `services/auth_service.py`
2. Show before/after for _verify_2fa
3. Explain the new flow


ISSUE P3-3: UserService Bypasses AuthService
─────────────────────────────────────────────
PROBLEM:
- UserService.change_password() directly imports RefreshTokenRepository:
  ```python
  from app.repositories.refresh_token_repository import RefreshTokenRepository
  token_repo = RefreshTokenRepository(self.session)
  await token_repo.revoke_all_for_user(user.id)
  ```
- Bypasses service layer
- Inline import inside method (inconsistent)

REQUIRED FIX:
Choose ONE:

Option A: Inject AuthService into UserService
  - Add `self.auth_service = AuthService(session)` in __init__
  - Call `self.auth_service.revoke_all_sessions(user.id)`

Option B: Add dedicated method to AuthService
  - `revoke_all_sessions(user_id)` returns count
  - UserService calls this method

Option C: Accept inline repo as OK for this case
  - Move import to top of file
  - Add comment explaining why direct repo is used

Choose Option A or B (preferred).

DELIVERABLE:
1. Updated `services/user_service.py`
2. Updated `services/auth_service.py` if needed
3. Before/after comparison


ISSUE P3-4: Inconsistent Import Style
──────────────────────────────────────
PROBLEM:
- Some imports at top of file
- Some imports inside methods (lazy/inline)
- Example in `services/user_service.py`:
  ```python
  async def change_password(self, ...):
      from app.repositories.refresh_token_repository import RefreshTokenRepository
  ```

REQUIRED FIX:
- Move all imports to top of file
- EXCEPT: Circular dependency prevention (if needed)
- Document any intentional inline imports
- Consistent style across all services

DELIVERABLE:
1. Updated service files with consistent imports
2. List any justified inline imports


ISSUE P3-5: File/Class Naming Confusion
────────────────────────────────────────
PROBLEM:
- `services/social_auth_service.py` (Logic + HTTP)
- `core/security/oauth.py` (Config only)
- Confusing which does what

REQUIRED FIX:
Choose ONE:

Option A: Rename file
  - `services/social_auth_service.py` → `services/oauth_service.py`
  - Update all imports

Option B: Keep name, clarify in docstrings
  - Already done (this is fine)
  - Just add cross-references

Option C: Merge into core/security/oauth.py
  - Not recommended (mixing concerns)

Choose Option A or B.

DELIVERABLE:
1. Renamed file (if Option A)
2. Updated imports across codebase
3. Cross-reference comments


ISSUE P3-6: TOTP Module Backup Code Function Unused
────────────────────────────────────────────────────
PROBLEM:
- `core/security/totp.py` has `verify_backup_code(code, stored_codes) -> Optional[int]`
- `services/totp_service.py` has its own `verify_backup_code` method
- The primitive is not being used

REQUIRED FIX:
Either:
Option A: Use the primitive in the service
  - Service calls `verify_backup_code_primitive(code, hashes)`
  - Then handles removal

Option B: Remove the primitive
  - Since service has its own logic
  - Reduces duplication

Choose Option A (preferred — DRY).

DELIVERABLE:
1. Updated `services/totp_service.py`
2. Show usage of primitive
3. Verify no duplication


═══════════════════════════════════════════════════════════════
ADDITIONAL REQUIREMENTS FOR ALL FIXES
═══════════════════════════════════════════════════════════════

For EVERY file you provide:

1. ✅ Complete file content (not snippets)
2. ✅ Line-by-line comments for changes
3. ✅ Type hints properly used
4. ✅ Docstrings updated
5. ✅ Industry-standard quality
6. ✅ No new issues introduced
7. ✅ Backward compatibility (if applicable)
8. ✅ Clear explanation of what changed and why

VERIFY AFTER FIXES:
- [ ] All imports resolve correctly
- [ ] No circular dependencies
- [ ] Services use services (not repositories) — layering maintained
- [ ] Token hashing in `core/security/tokens.py`
- [ ] BaseService decision made and applied
- [ ] No sync/async mixing in email
- [ ] Consistent import style
- [ ] Tests still pass (if any)
- [ ] Logging still works
- [ ] No duplicate logic

PROVIDE FIXES IN THIS ORDER:
1. `app/core/security/tokens.py` (NEW FILE - Issue P2-1)
2. `app/core/security/__init__.py` (update exports)
3. `app/services/auth_service.py` (Issues P2-1, P3-2)
4. `app/services/user_service.py` (Issues P3-3, P3-4)
5. `app/services/product_service.py` (Issue P3-1 if applicable)
6. `app/services/totp_service.py` (Issues P3-1, P3-6)
7. `app/services/base/base_service.py` (Issue P3-1 decision)
8. `app/services/email_service.py` (Issues P2-2, P2-3, P2-4)
9. `app/services/social_auth_service.py` (Issue P3-5 if renamed)
10. `app/services/__init__.py` (exports if needed)

AT THE END, PROVIDE:
- Summary table of changes
- Impact analysis (what changed in each file)
- Verification checklist showing all issues fixed
- Any new files created
- Any files deleted
- Any breaking changes (if any)
- Migration notes if applicable
- Testing recommendations

═══════════════════════════════════════════════════════════════
CONSTRAINTS
═══════════════════════════════════════════════════════════════

- Do NOT overwrite my existing code (only provide fixes)
- Maintain backward compatibility where reasonable
- Follow existing patterns (facade, service layer, etc.)
- Keep the excellent documentation style
- Preserve type safety
- Preserve security features
- Keep async-first design
- Do NOT add new features (only fix issues)
- Explain the WHY behind each change
```

---

## 🎯 **How to Use This Prompt**

### **Option 1: Fix Everything at Once**
Copy the entire prompt above and send it. You'll get all fixes in one go.

### **Option 2: Fix Phase 2 First**
```
"Fix all Phase 2 issues only (P2-1 through P2-4)"
```

### **Option 3: Fix Phase 3 First**
```
"Fix all Phase 3 issues only (P3-1 through P3-6)"
```

### **Option 4: Fix Specific Issues**
```
"Fix only P3-1 (BaseService) and P3-2 (AuthService → TotpService)"
```

### **Option 5: Ask for Approach First**
```
"Before fixing, explain the pros/cons of each option in P3-1 and P3-3"
```

---

## 📊 **Expected Output Structure**

When you use this prompt, you'll get:

```
📄 File 1: app/core/security/tokens.py (NEW)
   - Complete code
   - Functions: hash_refresh_token, generate_raw_refresh_token
   - Constants: TOKEN_BYTES, TOKEN_HASH_LENGTH
   - What changed and why

📄 File 2: app/core/security/__init__.py (updated)
   - Added token exports
   - What changed

📄 File 3: app/services/auth_service.py (fixed)
   - Fixed Issues: P2-1, P3-2
   - Uses TotpService instead of TotpSecretRepository
   - Imports from core.security.tokens
   - Complete code
   - Before/after comparison

📄 File 4: app/services/user_service.py (fixed)
   - Fixed Issues: P3-3, P3-4
   - Uses AuthService for session revocation
   - Consistent import style
   - Complete code

📄 File 5: app/services/product_service.py (updated if P3-1)
   - Inherits from BaseService (if Option A)
   - Complete code

📄 File 6: app/services/totp_service.py (fixed)
   - Fixed Issues: P3-1, P3-6
   - Uses primitive for backup code verification
   - Complete code

📄 File 7: app/services/base/base_service.py (decision)
   - Kept / Removed / Modified
   - Explanation

📄 File 8: app/services/email_service.py (fixed)
   - Fixed Issues: P2-2, P2-3, P2-4
   - Removed sync functions (Option A)
   - OR deprecation warnings (Option B)
   - Fixed URL building
   - Complete code

📄 File 9: app/services/social_auth_service.py (renamed if P3-5)
   - Renamed to oauth_service.py OR kept
   - Updated imports

📄 File 10: app/services/__init__.py (updated)
   - Exports adjusted

✅ Summary Table
✅ Impact Analysis
✅ Verification Checklist
✅ Migration Notes
✅ Testing Recommendations
```

---

## 💡 **Pro Tips**

### **Tip 1: Add Priority**
```
"Focus on CRITICAL issues first (P3-1, P3-2), 
then IMPORTANT (P2-1, P3-3), 
then NICE-TO-HAVE (P3-5, P3-6)"
```

### **Tip 2: Ask for Tests**
```
"For each fix, also provide a test example showing 
the fix works correctly"
```

### **Tip 3: Ask for Diagrams**
```
"For P3-2 (AuthService → TotpService), provide a 
before/after architecture diagram"
```

### **Tip 4: Ask for Rollback Plan**
```
"For each change, include a rollback plan in case 
the fix causes issues"
```

### **Tip 5: Ask for Changelog**
```
"Provide a CHANGELOG.md entry for each fix"
```

---

## 🎯 **Quick Summary of Fixes**

| Issue | Priority | Impact | Effort |
|-------|----------|--------|--------|
| **P3-1: BaseService unused** | 🔴 Critical | Architecture | Medium |
| **P3-2: AuthService bypasses TotpService** | 🔴 Critical | Layering | Medium |
| **P2-1: Token hashing location** | 🟡 Important | Organization | Small |
| **P3-3: UserService → AuthService** | 🟡 Important | Layering | Small |
| **P2-2: Sync email functions** | 🟡 Important | Performance | Small |
| **P3-4: Inconsistent imports** | 🟢 Nice | Consistency | Small |
| **P3-5: File naming** | 🟢 Nice | Clarity | Small |
| **P3-6: Duplicate backup code logic** | 🟢 Nice | DRY | Small |
| **P2-3: Email URL building** | 🟡 Important | Correctness | Small |
| **P2-4: Email deprecation** | 🟢 Nice | Migration | Small |

---

**Ye prompt use karo aur saare Phase 2 & Phase 3 issues professionally fix ho jayenge!** 🎯

**Kya main abhi kisi specific issue ka fix provide karun?**
</USER_REQUEST>
<ADDITIONAL_METADATA>
The current local time is: 2026-09-16T10:07:09+05:00.

The user's current state is as follows:
Active Document: u:\New folder (2)\app\services\social_auth_service.py (LANGUAGE_PYTHON)
Cursor is on line: 533
Other open documents:
- u:\New folder (2)\app\services\social_auth_service.py (LANGUAGE_PYTHON)
</ADDITIONAL_METADATA>