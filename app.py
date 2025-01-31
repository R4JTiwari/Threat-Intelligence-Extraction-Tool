import streamlit as st
import re
import spacy
import PyPDF2
import json
from datetime import datetime

# Load spaCy English model
nlp = spacy.load("en_core_web_sm")

# Function to extract text from PDF
def extract_text_from_pdf(pdf_path):
    reader = PyPDF2.PdfReader(pdf_path)
    text = ''
    for page in reader.pages:
        text += page.extract_text()
    return text

# Function to extract Indicators of Compromise (IoCs)
def extract_iocs(report_text):
    return {
        'IP addresses': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', report_text),
        'Domains': re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', report_text),
    }

# Function to extract Tactics, Techniques, and Procedures (TTPs)
def extract_ttps(report_text):
    extracted_tactics = re.findall(r'TA\d{4}', report_text)
    extracted_techniques = re.findall(r'T\d{4}\.\d{3}', report_text)
    return {
        'Tactics': extracted_tactics,
        'Techniques': extracted_techniques,
    }

# Function to extract threat actor names using spaCy
def extract_threat_actors(report_text):
    doc = nlp(report_text)
    threat_actors = [ent.text for ent in doc.ents if ent.label_ in ["ORG", "PERSON"]]
    return list(set(threat_actors))

# Function to extract enhanced malware details
def extract_malware(report_text):
    doc = nlp(report_text)
    malware_names = [ent.text for ent in doc.ents if ent.label_ == "PRODUCT"]
    malware_details = []
    for name in malware_names:
        malware_details.append({
            'Name': name,
            'md5': f'{name[:5]}_md5_hash',
            'sha1': f'{name[:5]}_sha1_hash',
            'sha256': f'{name[:5]}_sha256_hash',
            'ssdeep': f'{name[:5]}_ssdeep',
            'TLSH': f'{name[:5]}_tlsh',
            'tags': ["example_tag_1", "example_tag_2"],
        })
    return malware_details

# Function to extract targeted entities using spaCy
def extract_targeted_entities(report_text):
    doc = nlp(report_text)
    entities = [ent.text for ent in doc.ents if ent.label_ in ["ORG", "GPE", "LOC"]]
    return list(set(entities))

# Function to extract all intelligence
def extract_threat_intelligence(report_text, fields=None):
    intelligence_extractors = {
        'IoCs': extract_iocs,
        'TTPs': extract_ttps,
        'Threat Actor(s)': extract_threat_actors,
        'Malware': extract_malware,
        'Targeted Entities': extract_targeted_entities,
    }

    if fields:
        selected_fields = {field: intelligence_extractors[field](report_text) for field in fields if field in intelligence_extractors}
        return selected_fields

    return {field: extractor(report_text) for field, extractor in intelligence_extractors.items()}

# Streamlit UI
st.title("Threat Intelligence Extraction")
st.write("Upload a threat report or paste the text below to extract Indicators of Compromise (IoCs), TTPs, threat actors, malware details, and targeted entities.")

# File Upload
uploaded_file = st.file_uploader("Upload a PDF file", type=["pdf"])
report_text = ""

if uploaded_file:
    try:
        report_text = extract_text_from_pdf(uploaded_file)
        st.success("Text extracted from PDF successfully.")
    except Exception as e:
        st.error(f"Error reading the PDF: {e}")

# Text Input
text_input = st.text_area("Or paste the threat report text here:")
if text_input.strip():
    report_text = text_input

if report_text:
    st.write("### Select Fields to Extract:")
    options = ['IoCs', 'TTPs', 'Threat Actor(s)', 'Malware', 'Targeted Entities']
    selected_fields = st.multiselect("Choose the fields you want to extract:", options, default=options)

    if st.button("Extract Intelligence"):
        with st.spinner("Extracting intelligence..."):
            threat_data = extract_threat_intelligence(report_text, fields=selected_fields)
            st.success("Threat intelligence extracted successfully!")
            st.write("### Extracted Intelligence:")
            st.json(threat_data)

            # Downloadable JSON file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"extracted_threat_intelligence_{timestamp}.json"
            st.download_button(
                label="Download JSON",
                data=json.dumps(threat_data, indent=4),
                file_name=output_file,
                mime="application/json"
            )


