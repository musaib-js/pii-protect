import pytest
import asyncio

from pii_protect import PIIMaskingEngine
from pii_protect.ner import NEREngine
from pii_protect.crypto import AESGCMCipher
from pii_protect.storage import FileSystemStorage, InMemoryStorage
from pii_protect.tokens import DeterministicTokenGenerator

salt = DeterministicTokenGenerator.generate_salt()
token_generator = DeterministicTokenGenerator(salt=salt)

SAMPLE_TEXT = "Contact john.doe@acme.com or +919812345678 about GST 27AAPFU0939F1ZV."
FIXED_KEY = AESGCMCipher.generate_key()

@pytest.mark.asyncio
async def test_bert_masks_realistic_vendor_document():
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

    ner = NEREngine(enable_bert=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
        token_generator=token_generator
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
async def test_bert_masks_large_procurement_document():
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

    ner = NEREngine(enable_bert=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
        token_generator=token_generator
    ) as engine:

        result = await engine.mask(text)

        assert result.token_count > 90

        restored = await engine.unmask(result.masked_text)

        assert restored == text


@pytest.mark.asyncio
async def test_bert_and_regex_work_together():
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

    ner = NEREngine(enable_bert=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
        token_generator=token_generator
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
async def test_bert_reuses_tokens_for_same_person_and_company():
    text = """
    Rahul Khanna from Wipro Limited approved the vendor registration.

    Rahul Khanna later reviewed the compliance documents submitted by
    Wipro Limited before the purchase order was released.
    """

    ner = NEREngine(enable_bert=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
        token_generator=token_generator
    ) as engine:

        result = await engine.mask(text)

        person_tokens = [
            entity.token for entity in result.entities if entity.entity_type == "PERSON"
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
async def test_bert_masks_business_correspondence():
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

    ner = NEREngine(enable_bert=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
        token_generator=token_generator
    ) as engine:

        result = await engine.mask(text)

        assert "{{PERSON:" in result.masked_text
        assert "{{ORGANISATION:" in result.masked_text
        assert "{{ADDRESS:" in result.masked_text

        restored = await engine.unmask(result.masked_text)

        assert restored == text
        
@pytest.mark.asyncio
async def test_aadhar_numbers():
    text = """
    Hi, my aadhar number is 889412412624 and 8894 1241 2624

    """

    ner = NEREngine(enable_bert=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
        token_generator=token_generator
    ) as engine:

        result = await engine.mask(text)

        assert "{{AADHAR:" in result.masked_text
        

        restored = await engine.unmask(result.masked_text)
        
        assert "889412412624" in restored
        assert "8894 1241 2624" in restored
                

        assert restored == text


@pytest.mark.asyncio
async def test_hi_not_masked():
    text = """
    Hi
    """

    ner = NEREngine(enable_bert=True)

    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        ner_engine=ner,
        token_generator=token_generator
    ) as engine:

        result = await engine.mask(text)

        assert "{{PERSON:" not in result.masked_text
        assert "Hi" in result.masked_text
