
# Threat Intelligence Extraction Tool

A powerful application built using Streamlit for extracting Indicators of Compromise (IoCs), Tactics, Techniques, and Procedures (TTPs), Threat Actors, Malware Details, and Targeted Entities from cyber threat reports. The tool leverages Natural Language Processing (NLP) and regex-based techniques for rapid and accurate intelligence extraction.

## Features

- **PDF Upload Support**: Extract text directly from uploaded PDF reports.
- **Text Input**: Paste raw text for processing.
- **Field Selection**: Customize your extraction by selecting from IoCs, TTPs, Threat Actors, Malware, and Targeted Entities.
- **JSON Output**: View and download the extracted intelligence as a structured JSON file.
- **Simple and Interactive UI**: Built with Streamlit for a clean and responsive user experience.
- **Flexible Intelligence Extraction**: Choose to extract specific fields or all available intelligence from the report.
- **Real-Time Insights**: Quickly analyze reports for actionable threat intelligence.

## Technologies Used

- **Streamlit**: Frontend framework for building interactive web applications.
- **spaCy**: NLP library for named entity recognition and text processing.
- **PyPDF2**: Extracts text from PDF files.
- **Python**: Core programming language used to build the application.
- **Regex**: Identifies patterns like IP addresses, domains, and TTPs.

## Setup Instructions

### Prerequisites

Ensure the following are installed on your system:

- Python 3.8 or above
- pip (Python package manager)

### Installation Steps

1. Clone the repository:

    
    git clone https://github.com/your-repo/threat-intelligence-tool.git
    cd threat-intelligence-tool
    

2. Install required dependencies:
    
    pip install -r requirements.txt
    python -m spacy download en_core_web_sm
    

3. Run the application:
    
    streamlit run app.py
    

4. Open the app:  
    The Streamlit app will open automatically in your default web browser. If not, navigate to the URL provided in the terminal (e.g., `http://localhost:8501`).

## Usage

- **Upload a PDF File**: Click the 'Browse Files' button and select a threat report in PDF format.
- **Paste Text**: Alternatively, paste the threat report text into the provided text area.
- **Select Fields**: Choose the intelligence fields you want to extract.
- **Extract Intelligence**: Click the 'Extract Intelligence' button to process the report and display the results.
- **Download Results**: Download the JSON file containing the extracted intelligence.
- **Save Unique Results**: Each extraction is saved with a unique timestamp to avoid overwriting files.

## Hackathon Value Proposition

### Innovation

This tool provides a comprehensive, user-friendly interface for extracting threat intelligence, which is crucial for cybersecurity professionals and organizations.

### Scalability

With modular extraction functions, it can be expanded to support additional fields, languages, or input formats.

### Impact

Enhances the speed and accuracy of threat analysis, enabling quicker responses to cyber threats.

## Contributors

- Raj Tiwari
- Shivansh Dixit
- Prakhar Shukla

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For any queries or support, please contact us at your-mistzord@gmail.com.
