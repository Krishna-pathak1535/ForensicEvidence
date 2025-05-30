# 🔒 Forensic Evidence Management System 🔗

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![GitHub last commit](https://img.shields.io/github/last-commit/Krishna-pathak1535/forensicevidence?style=for-the-badge)](https://github.com/Krishna-pathak1535/forensicevidence/commits/main)

---

## ✨ Introduction

In an increasingly digital world, the integrity and immutability of forensic evidence are paramount. The **Forensic Evidence Management System** is a cutting-edge web application built with Flask, designed to ensure the tamper-proof storage and verifiable chain of custody for digital evidence. By leveraging a robust blockchain-like structure and advanced encryption, this system provides a secure, transparent, and efficient solution for forensic investigators and legal professionals to manage critical digital assets with unwavering trust.

---

## 🚀 Key Features

* **Secure User Authentication & Authorization:** Robust user registration and login with `bcrypt` hashed passwords. Features role-based access control, including an administrative panel for comprehensive system management.

* **Advanced Evidence Encryption:** All uploaded evidence files are immediately encrypted using `AES` (Advanced Encryption Standard) before storage, guaranteeing the confidentiality of sensitive data.

* **Immutable Blockchain Ledger:**

    * Each piece of digital evidence is recorded as a unique "block" in a sequential, time-stamped chain.

    * Cryptographic hashing of encrypted evidence ensures that even the slightest alteration to the data is detectable.

    * A **Proof of Work (PoW)** mechanism secures the chain, making it computationally infeasible to tamper with past records without re-mining all subsequent blocks.

* **Verifiable Chain of Custody:** The inherent cryptographic linking of blocks provides an undeniable, chronological record of all evidence additions and interactions.

* **Comprehensive Blockchain Visibility:** A dedicated interface allows users to inspect the entire blockchain ledger, providing transparent access to all recorded evidence blocks and their associated metadata.

* **Automated Integrity Verification:** The system includes a powerful tool to automatically verify the integrity of the entire blockchain, instantly detecting any unauthorized modifications or tampering attempts.

* **Secure Evidence Download:** Authorized users can securely download original evidence files, which are decrypted on-the-fly for legitimate access.

---

## 💡 Purpose & Impact

This project directly addresses a critical challenge in digital forensics: maintaining the **unquestionable integrity and authenticity** of evidence from its collection to its presentation in a court of law.

* **For Law Enforcement & Forensic Labs:** Provides a reliable and legally sound system for storing digital evidence, ensuring its admissibility in legal proceedings by guaranteeing its unaltered state.

* **For Legal Professionals:** Offers a transparent and verifiable record of evidence, significantly strengthening legal cases by providing an undeniable and auditable chain of custody.

* **Combating Digital Tampering:** The integrated blockchain and Proof of Work mechanisms create a formidable barrier against unauthorized alteration, making it extremely difficult and immediately detectable for anyone to manipulate evidence records once they are committed to the chain.

* **Streamlined Workflow:** Automates the complex process of recording, securing, and verifying digital evidence, thereby reducing manual overhead, minimizing human error, and accelerating investigative timelines.
  
---

## 🛠️ Getting Started

Follow these steps to get your Forensic Evidence Management System up and running locally.

### Prerequisites

* **Python 3.9+** (Ensure Python is installed and added to your system's PATH.)

* **`pip`** (Python package installer, usually comes with Python.)

* **Git** (For cloning the repository.)

### Installation Steps

1.  **Clone the Repository:**
    Open your terminal or command prompt and execute the following command to clone the project to your local machine:
    ```bash
    git clone [https://github.com/Krishna-pathak1535/forensicevidence.git](https://github.com/Krishna-pathak1535/forensicevidence.git)
    cd forensicevidence
    ```

2.  **Create a Virtual Environment (Recommended):**
    It's best practice to work within a virtual environment to manage project dependencies.
    ```bash
    python -m venv venv
    ```
    * **On Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    * **On macOS / Linux:**
        ```bash
        source venv/bin/activate
        ```

3.  **Install Dependencies:**
    With your virtual environment activated, install all required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

### Running the Application

1.  **Start the Flask Server:**
    Ensure your virtual environment is active, then run the main application file:
    ```bash
    python app.py
    ```
    You should see output indicating that the Flask development server is running, typically on `http://127.00.1:5000/` or `http://localhost:5000/`.

2.  **Initial Database Setup (Automatic):**

    * Upon the very first run of `app.py`, a SQLite database file named `blockchain.db` will be automatically created in your project's root directory.

    * A **genesis block** (the foundational first block of the blockchain) will be added to the database.

    * A default **administrator user** will be created with the following credentials:

        * **Username:** `admin`

        * **Password:** `admin`

        * **Security Note:** It is **highly recommended** to change the password for this default admin user immediately after your first successful login for security purposes.

3.  **Access the Web Interface:**
    Open your preferred web browser and navigate to the address provided by the Flask server (e.g., `http://127.0.0.1:5000/`). You will be redirected to the login page.

---

## 🖥️ Usage Details

Once the application is running, you can interact with it through the web interface.

### 1. Registering a New User

* **Navigate:** From the login page, click on the **"Register here"** link.

* **Input:** Enter a desired `Username` and `Password`.

* **Submit:** Click the "Register" button.

* **Outcome:** You will receive a success message and be redirected to the login page to sign in with your new credentials.

### 2. Logging In

* **Navigate:** Go to the application's base URL (e.g., `http://127.0.0.1:5000/`) or the `/login` route.

* **Input:** Enter your `Username` and `Password`.

* **Submit:** Click the "Login" button.

* **Outcome:** Upon successful login, you will be redirected to the "Upload Evidence File" page.

### 3. Uploading Evidence Files

* **Access:** After logging in, you will be on the `/upload` page.

* **Select File:** Click "Choose File" and select any digital file from your computer (e.g., a document, image, video).

* **Process:** Click the **"Upload & Store on Blockchain"** button.

* **Behind the Scenes:**

    * The selected file is read and immediately **encrypted** using AES.

    * A cryptographic **hash** of the *encrypted* file is generated (this is the `evidence_hash`).

    * A new **block** is created, containing the file's metadata (index, timestamp, filename), the `evidence_hash`, and the `block_hash` of the previous block in the chain.

    * The system performs a **Proof of Work** calculation to find a valid `nonce` for this new block.

    * The encrypted file is saved to the `uploads/` directory on the server.

    * The new block's data is recorded in the `blockchain.db` database.

* **Outcome:** A success message will be displayed, and the "Recent Blockchain Records" table on the page will update to show your newly added block.

### 4. Viewing the Full Blockchain Ledger

* **Access:** From the "Upload Evidence File" page, click the **"View Full Blockchain"** button.

* **Outcome:** You will be taken to the `/chain` page, which displays a detailed table of every block currently in the blockchain, including its index, timestamp, filename, evidence hash, previous block's hash, nonce, and its own block hash. This provides a transparent view of the entire chain of custody.

### 5. Verifying Blockchain Integrity

* **Access:** From the "Upload Evidence File" page, click the **"Verify Blockchain"** button.

* **Process:** The system will traverse the entire blockchain, performing critical checks:

    * It verifies that each block's `previous_hash` correctly matches the `block_hash` of the preceding block.

    * It recomputes the hash for each block based on its stored data and verifies it matches the `block_hash` recorded in the database.

    * It checks if each block's `block_hash` still meets the Proof of Work difficulty requirement (starts with the required number of leading zeros).

* **Outcome:**

    * **"Blockchain Integrity: VERIFIED"**: If all checks pass, indicating the chain is intact and untampered.

    * **"Blockchain Integrity: COMPROMISED"**: If any discrepancies are found, along with specific messages detailing which blocks failed validation and why (e.g., "previous hash mismatch," "hash mismatch," "does not meet proof of work difficulty").

### 6. Downloading Evidence Files

* **Access:** Go to the "View Full Blockchain" page (`/chain`).

* **Download:** In the table, click on the **"Filename"** of the evidence you wish to download.

* **Behind the Scenes:**

    * The system retrieves the encrypted file from the `uploads/` directory.

    * The encrypted file is **decrypted** using the stored key and IV.

    * The original, decrypted file is sent back to your browser.

* **Outcome:** Your browser will prompt you to download the original, unencrypted evidence file.

### 7. Admin Panel Access

* **Access:** If logged in as the `admin` user, a **"Admin Dashboard"** link will appear in the navigation bar.

* **Functionality:** The admin panel (powered by Flask-Admin) allows administrators to:

    * Manage users (e.g., create new users, change passwords, assign admin roles).

    * View and manage blockchain records directly (though direct manipulation here would break chain integrity, it's useful for oversight).

* **Security Note:** Access to this panel is restricted to authenticated users with `is_admin` set to `True`.

### 8. Logging Out

* **Access:** Click the **"Logout"** button available on most authenticated pages (e.g., "Upload Evidence File" page).

* **Outcome:** Your session will be terminated, and you will be redirected to the login page.

---

## 📂 Project Structure

```
.
├── app.py                  # Main Flask application, blockchain logic, routes, database models
├── encrypt.py              # Python module for AES file encryption/decryption utilities
├── requirements.txt        # List of Python dependencies for the project
├── test_crypto.py          # Simple test script to verify PyCryptodome installation
├── uploads/                # Directory where encrypted evidence files are securely stored
└── templates/              # HTML templates rendered by Flask
    ├── base.html           # Base template for consistent page layout and navigation
    ├── chain.html          # Displays the full blockchain ledger in a table format
    ├── login.html          # User login interface
    ├── register.html       # User registration interface
    ├── upload.html         # Interface for uploading new evidence files
    └── verify.html         # Displays the results of the blockchain integrity verification
```

---

## ⚙️ Technologies Used

* **Backend:**

    * **Flask:** A lightweight Python web framework for building the application.

    * **Flask-SQLAlchemy:** An Object Relational Mapper (ORM) for managing the SQLite database (`blockchain.db`).

    * **Flask-Bcrypt:** Provides bcrypt hashing utilities for secure password storage.

    * **Flask-Login:** Manages user sessions and authentication.

    * **Flask-Admin:** Provides a customizable administrative interface for database models.

    * **PyCryptodome:** A comprehensive cryptographic library used for AES encryption and SHA-256 hashing.

* **Frontend:**

    * **HTML5:** Structure of the web pages.

    * **Tailwind CSS:** A utility-first CSS framework for rapid and responsive styling.

    * **JavaScript:** For dynamic client-side interactions and the interactive blockchain demo.

    * **Chart.js:** A powerful JavaScript charting library for rendering interactive data visualizations on HTML Canvas.

---

## ✉️ Contact

Feel free to reach out if you have any questions, feedback, or collaboration inquiries!

* **Email:** krishna.pathak2003@gmail.com

* **GitHub:** [Krishna-pathak1535](https://github.com/Krishna-pathak1535)

* **LinkedIn:** [Krishnanand Pathak](https://www.linkedin.com/in/krishnanand-pathak/)

---

