# Agentic Forensic Investigator 🦇

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey)

**The Dark Knight of Digital Forensics.**

The **Agentic Forensic Investigator** is a powerful tool that combines the memory forensics capabilities of **Volatility 3** with the intelligence of **Large Language Models (LLMs)**. It allows users to conduct complex investigations using natural language, automating the planning, execution, and analysis phases.

## ✨ Key Features

-   **🧠 Dual LLM Support**: Choose between **Cloud (OpenAI)** for maximum intelligence or **Local (Ollama)** for privacy and offline capability.
-   **📝 Automated Planning**: The agent translates your high-level scenario (e.g., "Check for malware") into a precise list of Volatility 3 plugins.
-   **⚡ Smart Execution**: Automatically runs the selected plugins against the memory image.
-   **🔍 AI Analysis**: Analyzes the output of each plugin to highlight suspicious findings and explain them in plain English.
-   **📊 Interactive Reporting**: Generates a beautiful HTML report with:
    -   Executive Summary
    -   Investigation Flowchart (Mermaid.js)
    -   Expandable Detailed Findings
    -   Raw Output Access

## 🤖 Choosing Your AI Brain

| Feature | **Cloud (OpenAI)** | **Local (Ollama)** |
| :--- | :--- | :--- |
| **Intelligence** | High (GPT-4o) | Medium (Llama 3) |
| **Speed** | Fast | Hardware Dependent |
| **Privacy** | Data sent to OpenAI | **100% Private** |
| **Internet** | Required | **Offline Capable** |
| **Cost** | Paid (API Key) | Free |
| **Best For** | Complex scenarios, deep analysis | Sensitive data, air-gapped systems |

## 🚀 Getting Started

### Prerequisites

-   Python 3.8+
-   [Ollama](https://ollama.com) (Optional, for local mode)

### Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/YOUR_USERNAME/agentic-forensic-investigator.git
    cd agentic-forensic-investigator
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Setup Volatility 3**:
    Run the setup script to clone Volatility 3 and install its requirements:
    ```bash
    python setup_env.py
    ```

4.  **Local Mode Setup (Optional)**:
    If you want to use the local LLM, ensure Ollama is running:
    ```bash
    ollama serve
    ollama pull llama3
    ```

## 🕵️ Usage

Start the investigator:
```bash
python forensic_agent.py
```

**Note**: If you choose **OpenAI**, you will be asked to enter your API Key. You can get one from [OpenAI Platform](https://platform.openai.com/api-keys).

### Workflow
1.  **Select AI Brain**: Choose Option 1 (OpenAI) or Option 2 (Ollama).
2.  **Provide Image**: Enter the path to the memory image (e.g., `imagery.raw`).
3.  **Describe Scenario**: Tell the agent what to look for (e.g., "I suspect a rootkit hiding processes").
4.  **Review Plan**: The agent will propose a list of plugins. Approve it to proceed.
5.  **View Report**: Open the generated `investigation_report.html` to see the results.

## 🔮 Future Enhancements
-   Add support for more LLM providers (Anthropic, Azure).
-   Implement a GUI for easier file selection.
-   Add "Human-in-the-loop" mode to edit the plan before execution.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ✍️ Author

Created by **Ishan Perera**.
