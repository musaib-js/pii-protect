"""
tests.test_ph_ids_and_ignore
===============================
Coverage for:
  - Philippines-specific regex entities: TIN, PH_GOVT_ID, STUDENT_ID,
    MEDICAL_RECORD_NUMBER.
  - Labelled PIN/OTP detection (a 4-6 digit code near the word PIN/OTP).
  - The ``ignore_entities`` parameter on mask()/mask_dict()/redact(),
    which lets a caller opt specific entity types out of masking.

Author: Musaib Altaf
"""

import pytest

from pii_protect import PIIMaskingEngine
from pii_protect.crypto import AESGCMCipher
from pii_protect.storage import InMemoryStorage
from pii_protect.tokens import DeterministicTokenGenerator
from pii_protect.types import EntityType

salt = DeterministicTokenGenerator.generate_salt()
token_generator = DeterministicTokenGenerator(salt=salt)
FIXED_KEY = AESGCMCipher.generate_key()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text,expected_type,leaked_fragment",
    [
        ("TIN: 123-456-789-000", "TIN", "123-456-789-000"),
        ("Please provide your TIN 123-456-789 for the BIR form.", "TIN", "123-456-789"),
        ("SSS Number: 34-1234567-8", "PH_GOVT_ID", "34-1234567-8"),
        ("PhilHealth ID: 12-345678901-2", "PH_GOVT_ID", "345678901"),
        ("Pag-IBIG Number: 1234-5678-9012", "PH_GOVT_ID", "1234-5678-9012"),
        ("PhilSys ID: 1234-5678-9012-3456", "PH_GOVT_ID", "1234-5678-9012-3456"),
        ("Student ID: 2021-04567", "STUDENT_ID", "2021-04567"),
        ("Matriculation No: SID-20-004521", "STUDENT_ID", "SID-20-004521"),
        ("Medical Record Number: MRN-208734", "MEDICAL_RECORD_NUMBER", "MRN-208734"),
        ("Patient ID: P-00234891", "MEDICAL_RECORD_NUMBER", "P-00234891"),
    ],
)
async def test_ph_entities_are_masked(text, expected_type, leaked_fragment):
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        result = await engine.mask(text)
        assert f"{{{{{expected_type}:" in result.masked_text
        assert leaked_fragment not in result.masked_text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text,expected_type",
    [
        ("Your OTP is 483920, valid for 5 minutes.", "OTP"),
        ("PIN: 4821", "PIN"),
        ("Enter your pin 993201 to continue.", "PIN"),
    ],
)
async def test_pin_and_otp_codes_are_masked(text, expected_type):
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        result = await engine.mask(text)
        assert f"{{{{{expected_type}:" in result.masked_text


@pytest.mark.asyncio
async def test_otp_pin_does_not_partially_match_a_longer_number():
    # A 7+ digit run near the label must not be partially captured (V-16/V-17 style bug).
    text = "reference number near OTP: 1234567 stays as-is"
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        result = await engine.mask(text)
        assert result.masked_text == text


@pytest.mark.asyncio
async def test_mask_ignore_entities_leaves_matching_types_untouched():
    text = "PIN: 4821, TIN: 123-456-789-000, contact test@example.com"
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        result = await engine.mask(text, ignore_entities=["PIN", "TIN"])
        assert "PIN: 4821" in result.masked_text
        assert "TIN: 123-456-789-000" in result.masked_text
        assert "{{EMAIL:" in result.masked_text
        assert "test@example.com" not in result.masked_text


@pytest.mark.asyncio
async def test_mask_ignore_entities_accepts_entity_type_enum():
    text = "PIN: 4821, contact test@example.com"
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        result = await engine.mask(text, ignore_entities=[EntityType.PIN])
        assert "PIN: 4821" in result.masked_text
        assert "{{EMAIL:" in result.masked_text


@pytest.mark.asyncio
async def test_mask_ignore_entities_is_case_insensitive():
    text = "PIN: 4821"
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        result = await engine.mask(text, ignore_entities=["pin"])
        assert result.masked_text == text


@pytest.mark.asyncio
async def test_redact_ignore_entities_leaves_matching_types_untouched():
    text = "PIN: 4821, contact test@example.com"
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        redacted = engine.redact(text, ignore_entities=["PIN"])
        assert "PIN: 4821" in redacted
        assert "[REDACTED:EMAIL]" in redacted


@pytest.mark.asyncio
async def test_mask_dict_ignore_entities_applies_to_every_leaf():
    data = {"note": "PIN: 4821", "email": "test@example.com"}
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        result = await engine.mask_dict(data, ignore_entities=["PIN"])
        assert result["note"] == "PIN: 4821"
        assert "{{EMAIL:" in result["email"]
