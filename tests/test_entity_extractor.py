import pytest
from app.services.entity_extractor import entity_extractor

def test_extract_phone_numbers():
    text = "Call officer at +91 98401 23456 or alternate number 9876543210 immediately."
    entities = entity_extractor.extract_all(text)
    assert "9840123456" in entities.phone_numbers
    assert "9876543210" in entities.phone_numbers

def test_extract_upi_ids():
    text = "Pay your bill to tneb.bill@paytm or support@okhdfcbank to avoid penalty."
    entities = entity_extractor.extract_all(text)
    assert "tneb.bill@paytm" in entities.upi_ids
    assert "support@okhdfcbank" in entities.upi_ids

def test_extract_urls_and_domains():
    text = "Check http://sbi-verification.xyz/portal and https://www.hdfcbank.com/login"
    entities = entity_extractor.extract_all(text)
    assert len(entities.urls) == 2
    assert "sbi-verification.xyz" in entities.domains
    assert "hdfcbank.com" in entities.domains

def test_extract_organizations():
    text = "Important notice from State Bank of India and TNEB regarding your account."
    entities = entity_extractor.extract_all(text)
    assert any("State Bank of India" in org or "SBI" in org for org in entities.organizations)
    assert "TNEB" in entities.organizations
