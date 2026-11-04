"""
tests.test_dates
=================
Coverage for date detection: DATE_OF_BIRTH and CARD_EXPIRY. Both patterns
are gated on a nearby label (see _DOB_CONTEXT_RE / _CARD_EXPIRY_CONTEXT_RE
in pii_protect.ner.engine), so an ordinary date in prose is left alone.

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
        ("My card expires 12/25.", "CARD_EXPIRY", "12/25"),
        ("Valid thru 09/2027.", "CARD_EXPIRY", "09/2027"),
        ("Date of Birth: Jan. 15, 1995 in bangalore. karnataka, india", "DATE_OF_BIRTH", "Jan. 15, 1995"),
        ("I was born in 15. jan, 1984 in bangalore. karnataka, india", "DATE_OF_BIRTH", "15. jan, 1984"),
    ],
)
async def test_dates_are_masked(text, expected_type, leaked_fragment):
    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        token_generator=token_generator,
    ) as engine:
        result = await engine.mask(text)
        print(result)
        assert f"{{{{{expected_type}:" in result.masked_text
        assert leaked_fragment not in result.masked_text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text",
    [
        "The report is dated 15 March 1995.",
        "The invoice date is 1995-03-15.",
        "Meeting on 12/25 at the office.",
    ],
)
async def test_dates_without_a_label_are_left_alone(text):
    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        token_generator=token_generator,
    ) as engine:
        result = await engine.mask(text)
        assert result.masked_text == text


@pytest.mark.asyncio
async def test_full_date_is_not_partially_matched_as_card_expiry():
    text = "Date of Birth: 15/03/1995, card expiry 12/25"
    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        token_generator=token_generator,
    ) as engine:
        result = await engine.mask(text)
        assert "15/03/1995" not in result.masked_text
        assert "12/25" not in result.masked_text
        assert result.masked_text.count("{{DATE_OF_BIRTH:") == 1
        assert result.masked_text.count("{{CARD_EXPIRY:") == 1


@pytest.mark.asyncio
async def test_date_entities_can_be_ignored():
    text = "Date of Birth: 15 March 1995, card expiry 12/25"
    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        token_generator=token_generator,
    ) as engine:
        result = await engine.mask(
            text, ignore_entities=[EntityType.DATE_OF_BIRTH, EntityType.CARD_EXPIRY]
        )
        assert result.masked_text == text
