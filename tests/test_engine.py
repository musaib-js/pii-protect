"""
tests.test_engine
====================
Smoke tests for PIIMaskingEngine covering mask/unmask round-trips,
deduplication, and irreversible redact(), against both InMemoryStorage
and FileSystemStorage.

Author: Musaib Altaf
"""

import pytest

from pii_protect import PIIMaskingEngine
from pii_protect.ner import NEREngine
from pii_protect.crypto import AESGCMCipher
from pii_protect.storage import FileSystemStorage, InMemoryStorage

SAMPLE_TEXT = "Contact john.doe@acme.com or +919812345678 about GST 27AAPFU0939F1ZV."
FIXED_KEY = AESGCMCipher.generate_key()


@pytest.mark.asyncio
async def test_mask_unmask_roundtrip_memory():
    async with PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=FIXED_KEY) as engine:
        result = await engine.mask(SAMPLE_TEXT)
        assert result.token_count > 0
        assert "john.doe@acme.com" not in result.masked_text
        assert "{{EMAIL:" in result.masked_text

        restored = await engine.unmask(result.masked_text)
        assert restored == SAMPLE_TEXT


@pytest.mark.asyncio
async def test_mask_unmask_roundtrip_filesystem(tmp_path):
    vault_path = tmp_path / "vault.json"
    async with PIIMaskingEngine(storage=FileSystemStorage(vault_path), encryption_key=FIXED_KEY) as engine:
        result = await engine.mask(SAMPLE_TEXT, scope="doc-1")
        restored = await engine.unmask(result.masked_text, scope="doc-1")
        assert restored == SAMPLE_TEXT

    assert vault_path.exists()

    # Re-open against the same file and confirm the vault persisted.
    async with PIIMaskingEngine(storage=FileSystemStorage(vault_path), encryption_key=FIXED_KEY) as engine:
        restored_again = await engine.unmask(result.masked_text, scope="doc-1")
        assert restored_again == SAMPLE_TEXT


@pytest.mark.asyncio
async def test_dedup_same_value_reuses_token():
    text = "Email john@acme.com twice: john@acme.com"
    async with PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=FIXED_KEY) as engine:
        result = await engine.mask(text, scope="doc-2")
        tokens = [e.token for e in result.entities if e.entity_type == "EMAIL"]
        assert len(tokens) == 2
        assert tokens[0] == tokens[1]  # same value -> same token


@pytest.mark.asyncio
async def test_redact_is_irreversible_and_stores_nothing():
    storage = InMemoryStorage()
    async with PIIMaskingEngine(storage=storage, encryption_key=FIXED_KEY) as engine:
        redacted = engine.redact(SAMPLE_TEXT)
        assert "john.doe@acme.com" not in redacted
        assert "[REDACTED:EMAIL]" in redacted
        assert len(storage) == 0  # redact() must never touch storage


@pytest.mark.asyncio
async def test_mask_dict_and_unmask_dict():
    data = {"contact": "john.doe@acme.com", "note": "call +919812345678"}
    async with PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=FIXED_KEY) as engine:
        masked = await engine.mask_dict(data)
        assert masked["contact"] != data["contact"]

        restored = await engine.unmask_dict(masked)
        assert restored == data



@pytest.mark.asyncio
async def test_engine_without_context_manager():
    engine = PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=FIXED_KEY)
    await engine.initialise()
    result = await engine.mask(SAMPLE_TEXT)
    assert result.token_count > 0
    assert "john.doe@acme.com" not in result.masked_text
    assert "{{EMAIL:" in result.masked_text
    restored = await engine.unmask(result.masked_text)
    assert restored == SAMPLE_TEXT  
    
    
@pytest.mark.asyncio
async def test_mask_dict_with_known_pii_keys_simple():
    data = {
        "vendor_name": "Acme Industries",
        "invoice_number": "INV-001",
        "amount": 1500,
    }

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
    ) as engine:
        masked = await engine.mask_dict_with_known_pii_keys(
            data,
            pii_keys=["vendor_name"],
        )

        assert masked["vendor_name"] != data["vendor_name"]
        assert "{{" in masked["vendor_name"]

        assert masked["invoice_number"] == data["invoice_number"]
        assert masked["amount"] == data["amount"]

        restored = await engine.unmask_dict_with_known_pii_keys(
            masked,
            pii_keys=["vendor_name"],
        )

        assert restored == data


@pytest.mark.asyncio
async def test_mask_dict_with_known_pii_keys_nested():
    data = {
        "invoice": {
            "vendor_name": "Acme Industries",
            "gst_number": "27AAPFU0939F1ZV",
        },
        "metadata": {
            "created_by": "system",
        },
    }

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
    ) as engine:

        masked = await engine.mask_dict_with_known_pii_keys(
            data,
            pii_keys=["vendor_name", "gst_number"],
        )

        assert "{{" in masked["invoice"]["vendor_name"]
        assert "{{" in masked["invoice"]["gst_number"]
        assert masked["metadata"]["created_by"] == "system"

        restored = await engine.unmask_dict_with_known_pii_keys(
            masked,
            pii_keys=["vendor_name", "gst_number"],
        )

        assert restored == data


@pytest.mark.asyncio
async def test_mask_dict_with_known_pii_keys_inside_list():
    data = {
        "vendors": [
            {
                "vendor_name": "ABC Pvt Ltd",
                "amount": 100,
            },
            {
                "vendor_name": "XYZ Pvt Ltd",
                "amount": 200,
            },
        ]
    }

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
    ) as engine:

        masked = await engine.mask_dict_with_known_pii_keys(
            data,
            pii_keys=["vendor_name"],
        )

        assert "{{" in masked["vendors"][0]["vendor_name"]
        assert "{{" in masked["vendors"][1]["vendor_name"]

        assert masked["vendors"][0]["amount"] == 100
        assert masked["vendors"][1]["amount"] == 200

        restored = await engine.unmask_dict_with_known_pii_keys(
            masked,
            pii_keys=["vendor_name"],
        )

        assert restored == data


@pytest.mark.asyncio
async def test_mask_dict_with_known_pii_keys_deeply_nested():
    data = {
        "a": {
            "b": [
                {
                    "c": {
                        "vendor_name": "Deep Vendor",
                    }
                }
            ]
        }
    }

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
    ) as engine:

        masked = await engine.mask_dict_with_known_pii_keys(
            data,
            pii_keys=["vendor_name"],
        )

        assert "{{" in masked["a"]["b"][0]["c"]["vendor_name"]

        restored = await engine.unmask_dict_with_known_pii_keys(
            masked,
            pii_keys=["vendor_name"],
        )

        assert restored == data


@pytest.mark.asyncio
async def test_mask_dict_with_known_pii_keys_deduplicates():
    data = {
        "vendor_name": "Acme Pvt Ltd",
        "nested": {
            "vendor_name": "Acme Pvt Ltd",
        },
    }

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
    ) as engine:

        masked = await engine.mask_dict_with_known_pii_keys(
            data,
            pii_keys=["vendor_name"],
        )

        assert masked["vendor_name"] == masked["nested"]["vendor_name"]

        restored = await engine.unmask_dict_with_known_pii_keys(
            masked,
            pii_keys=["vendor_name"],
        )

        assert restored == data
        
from pii_protect.ner import NEREngine


@pytest.mark.asyncio
async def test_gliner_masks_realistic_vendor_document():
    text = """
    Rajesh Sharma, Senior Procurement Manager at Tata Consultancy Services Limited,
    approved the onboarding of ABC Industrial Supplies Private Limited.

    The vendor operates from Plot No. 44, Electronic City Phase II,
    Bengaluru, Karnataka 560100.

    For payment queries, please contact rajesh.sharma@tcs.com or
    call +91 9876543210.

    GSTIN: 29AAACT2727Q1ZW
    PAN: AAACT2727Q
    IFSC: HDFC0000240
    Bank Account Number: 50200012345678

    Purchase Order: PO-2025-004281
    Invoice Number: INV-2025-1189
    """

    ner = NEREngine(enable_gliner=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
    ) as engine:

        result = await engine.mask(text)

        assert "{{PERSON:" in result.masked_text
        assert "{{ORGANISATION:" in result.masked_text
        assert "{{ADDRESS:" in result.masked_text

        assert "{{EMAIL:" in result.masked_text
        assert "{{PHONE:" in result.masked_text
        assert "{{GST:" in result.masked_text
        assert "{{PAN:" in result.masked_text

        restored = await engine.unmask(result.masked_text)

        assert restored == text


@pytest.mark.asyncio
async def test_gliner_masks_large_procurement_document():
    paragraph = """
    Amitabh Kulkarni from Larsen & Toubro Limited met Kavita Menon at the
    Hyderabad engineering office to discuss the EPC contract for Reliance
    Industries Limited.

    The meeting was conducted at L&T Technology Centre,
    HITEC City, Hyderabad, Telangana.

    All future communication should be coordinated with
    Nikhil Rao before the commercial agreement is signed.
    """

    text = paragraph * 150

    ner = NEREngine(enable_gliner=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
    ) as engine:

        result = await engine.mask(text)

        assert result.token_count > 100

        restored = await engine.unmask(result.masked_text)

        assert restored == text


@pytest.mark.asyncio
async def test_gliner_and_regex_work_together():
    text = """
    Vendor onboarding request

    Vendor:
    Infosys Limited

    Primary Contact:
    Rahul Verma

    Email:
    rahul.verma@infosys.com

    Mobile:
    +91 9812345678

    GST Number:
    29AAACI1681G1ZP

    PAN:
    AAACI1681G

    IFSC:
    ICIC0000104

    Account Number:
    009801000123456

    Office:
    Electronics City Phase I,
    Bengaluru,
    Karnataka 560100.
    """

    ner = NEREngine(enable_gliner=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
    ) as engine:

        result = await engine.mask(text)

        assert "{{PERSON:" in result.masked_text
        assert "{{ORGANISATION:" in result.masked_text
        assert "{{ADDRESS:" in result.masked_text

        assert "{{EMAIL:" in result.masked_text
        assert "{{PHONE:" in result.masked_text
        assert "{{GST:" in result.masked_text
        assert "{{PAN:" in result.masked_text
        assert "{{ACCOUNT:" in result.masked_text

        restored = await engine.unmask(result.masked_text)

        assert restored == text


@pytest.mark.asyncio
async def test_gliner_reuses_tokens_for_same_person_and_company():
    text = """
    Rahul Khanna from Wipro Limited approved the vendor registration.

    Rahul Khanna later reviewed the compliance documents submitted by
    Wipro Limited before the purchase order was released.
    """

    ner = NEREngine(enable_gliner=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
    ) as engine:

        result = await engine.mask(text)

        person_tokens = [
            entity.token
            for entity in result.entities
            if entity.entity_type == "PERSON"
        ]

        organisation_tokens = [
            entity.token
            for entity in result.entities
            if entity.entity_type == "ORGANISATION"
        ]

        assert len(person_tokens) >= 2
        assert len(organisation_tokens) >= 2

        assert len(set(person_tokens)) == 1
        assert len(set(organisation_tokens)) == 1

        restored = await engine.unmask(result.masked_text)

        assert restored == text


@pytest.mark.asyncio
async def test_gliner_masks_business_correspondence():
    text = """
    Dear Ms. Priya Menon,

    Thank you for participating in the commercial negotiations between
    Bharat Petroleum Corporation Limited and Siemens India Limited.

    Please review the revised quotation before forwarding it to
    Mr. Anurag Sinha.

    The signed agreement should be delivered to
    Prestige Tech Park,
    Marathahalli,
    Bengaluru,
    Karnataka.

    Regards,
    Vivek Sharma
    Commercial Contracts Team
    """

    ner = NEREngine(enable_gliner=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
    ) as engine:

        result = await engine.mask(text)

        assert "{{PERSON:" in result.masked_text
        assert "{{ORGANISATION:" in result.masked_text
        assert "{{ADDRESS:" in result.masked_text

        restored = await engine.unmask(result.masked_text)

        assert restored == text