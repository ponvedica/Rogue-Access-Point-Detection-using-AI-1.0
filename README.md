# Rogue Access Point Detection using AI

This project detects **Rogue (Evil Twin) Wi-Fi Access Points** using a combination of **heuristic network scanning** and **AI-powered traffic analysis**.  
It helps users identify fake Wi-Fi networks before connecting and analyzes connected networks for malicious behavior using trained neural network models.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Datasets](#datasets)
4. [Tech Stack](#tech-stack)
5. [Installation](#installation)
6. [Usage](#usage)
7. [AI Model](#ai-model)
8. [Limitations](#limitations)
9. [Contributors](#contributors)

---

## Overview

Public Wi-Fi networks can be easily exploited by attackers who create **Evil Twin** access points — fake networks that mimic legitimate ones.  
When users connect, attackers can intercept sensitive data through **Man-in-the-Middle (MITM)** attacks.

This project introduces a **two-stage detection system**:

- **Stage 1: Pre-Connection Scan** — Detects suspicious SSIDs using heuristic risk factors.
- **Stage 2: AI-Based Analysis** — Uses deep learning models to analyze network traffic and classify it as **Legitimate** or **Evil Twin**.

---

## Features

- 🔍 **Pre-Connection Scan** – Identifies open, duplicate, or suspicious Wi-Fi SSIDs.  
- 🤖 **AI-Powered Detection** – Analyzes network traffic using Deep Neural Networks.  
- 📊 **Risk Assessment** – Generates a **Safety Score** and **Evil Twin Probability**.  
- 🖥️ **Interactive Interface** – Built with Streamlit for simple, visual results.  
- 💾 **Dataset-Based Training** – Uses real-world network datasets for learning malicious patterns.  

---

## Datasets

The model is trained using combined data from:

| Dataset | Description |
|----------|--------------|
| **CIC-IDS2017** | Flow-level features of normal and malicious traffic from the Canadian Institute for Cybersecurity |
| **Kyoto Honeypot Dataset** | Real-world malicious traffic and attack data from Kyoto University |

> These datasets were merged and refined to create a custom **Evil Twin Detection Dataset**.

---

## Tech Stack

| Component | Technology |
|------------|-------------|
| **Language** | Python |
| **Frontend/UI** | Streamlit |
| **Machine Learning/AI** | Scikit-learn, TensorFlow/Keras |
| **Data Handling** | Pandas, NumPy |
| **System Interaction** | Netsh (Windows) / Airport (macOS) |
| **Packet Manipulation** | Scapy |

---

## Installation

### Prerequisites

- Python 3.8 or higher  
- Internet access for dataset download (optional)  

### Setup

```bash
git clone https://github.com/yourusername/rogue-ap-detection.git
cd rogue-ap-detection
pip install -r requirements.txt
```

## Usage 

### 1. Run the Application
```bash
streamlit run app.py
```

### 2. Perform a Pre-Connection Scan

Click **“Scan Networks”** to view nearby Wi-Fi networks.

The app assigns each network a **Risk Score** based on:
- Open connections  
- Duplicate SSIDs  
- Suspicious words (e.g., “Free”, “Public”, “Evil”)  

---

### 3. AI-Based Analysis

Connect to a Wi-Fi network.

The trained model analyzes the captured traffic and predicts:
- **Safety Score**  
- **Evil Twin Probability**  
- **Recommended Action**  

---

## AI Model

The detection model uses **Deep Neural Networks (DNNs)**, including **CNN** and **LSTM** architectures.

**Input Features:**
- Flow duration, packet count, and packet size  
- Forward/backward traffic statistics  
- TCP flag analysis (PSH, URG)  
- SSID keyword patterns  

**Output:**
- Classification: `Legitimate` or `Evil Twin`  
- Confidence-based **Safety Score**

---

## Limitations

- ❌ **No RF Fingerprinting** – Physical radio frequency features are not included due to dataset limitations.  
- ⚠️ **Dataset-Dependent** – Model accuracy depends on dataset quality and real-world similarity.  
- 🌐 **Platform Limitations** – Some scanning commands may differ across operating systems.  
