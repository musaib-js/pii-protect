"""
tests.test_vehicle_numbers
=============================
Coverage for VEHICLE_NUMBER detection (India, Philippines, US, UAE, Saudi
Arabia). Every pattern is gated on a nearby plate/vehicle/registration
label -- see _VEHICLE_CONTEXT_RE in pii_protect.ner.engine -- since the
bare shapes (a few letters plus a few digits) are common to a lot of
other identifiers. Also covers the IBAN/vehicle-number collision: the
Indian plate shape ("KA05MH1234") also matches the (very permissive)
IBAN pattern, so a nearby vehicle-context label must make VEHICLE_NUMBER
win instead.

Author: Musaib Altaf
"""

import pytest

from pii_protect import PIIMaskingEngine
from pii_protect.crypto import AESGCMCipher
from pii_protect.storage import InMemoryStorage
from pii_protect.tokens import DeterministicTokenGenerator

salt = DeterministicTokenGenerator.generate_salt()
token_generator = DeterministicTokenGenerator(salt=salt)
FIXED_KEY = AESGCMCipher.generate_key()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text,leaked_fragment",
    [
        ("Vehicle number KA05MH1234 was flagged for overspeeding.", "KA05MH1234"),
        ("Plate no: MH-12-AB-1234 seen near the mall.", "MH-12-AB-1234"),
        ("The license plate NBC 1234 belongs to a red sedan.", "NBC 1234"),
        ("Registration number ABC 1234 was reported to police.", "ABC 1234"),
        ("Vehicle number A 12345 registered in Dubai.", "A 12345"),
        ("License plate 7ABC123 recorded at checkpoint.", "7ABC123"),
    ],
)
async def test_vehicle_numbers_are_masked_when_labelled(text, leaked_fragment):
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        result = await engine.mask(text)
        assert "{{VEHICLE_NUMBER:" in result.masked_text
        assert leaked_fragment not in result.masked_text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text",
    [
        "The invoice code ABC1234 was generated today.",
        "Order NBC1234 shipped yesterday.",
        "Item code 7ABC123 was scanned at the warehouse.",
    ],
)
async def test_vehicle_shaped_codes_without_context_are_not_masked_as_vehicle(text):
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        result = await engine.mask(text)
        assert "{{VEHICLE_NUMBER:" not in result.masked_text


@pytest.mark.asyncio
async def test_indian_plate_wins_over_iban_when_vehicle_context_present():
    text = "Vehicle number KA05MH1234 was flagged for overspeeding."
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        result = await engine.mask(text)
        assert "{{VEHICLE_NUMBER:" in result.masked_text
        assert "{{IBAN:" not in result.masked_text


@pytest.mark.asyncio
async def test_real_iban_without_vehicle_context_is_still_detected_as_iban():
    text = "Please wire the funds to IBAN GB29NWBK60161331926819 by Friday."
    async with PIIMaskingEngine(
        storage=InMemoryStorage(), encryption_key=FIXED_KEY, token_generator=token_generator
    ) as engine:
        result = await engine.mask(text)
        assert "{{IBAN:" in result.masked_text
        assert "GB29NWBK60161331926819" not in result.masked_text
