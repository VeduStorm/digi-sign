from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QFileDialog, QLabel, QMessageBox,
    QFrame, QTabWidget
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QClipboard
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, load_pem_private_key
)
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import (
    Name, NameAttribute, ObjectIdentifier, CertificateBuilder,
    random_serial_number, BasicConstraints, load_pem_x509_certificate
)
import os
import tempfile
import sys
from datetime import datetime, timedelta, UTC
import base64

with open("details.txt", 'r') as file:
    content = file.read()

# Support for PyInstaller
def resource_path(relative_path):
    base_path = os.path.abspath(os.path.dirname(__file__))
    if hasattr(sys, '_MEIPASS'):
        base_path = os.path.join(tempfile.gettempdir(), "DigiSign")
    full_path = os.path.join(base_path, relative_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    return full_path

# Load stylesheet from file
def load_stylesheet(theme):
    file_path = resource_path(f"styles/{theme}_STYLESHEET.qss")
    try:
        with open(file_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: Stylesheet {file_path} not found.")
        return None
    except Exception as e:
        print(f"Error loading stylesheet {file_path}: {str(e)}")
        return ""


def generate_self_signed_cert():
    """Generate a self-signed certificate using private key."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()
    subject = issuer = Name([
        NameAttribute(ObjectIdentifier("2.5.4.3"), content)
    ])
    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    # Save private key and certificate
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    cert_pem = cert.public_bytes(Encoding.PEM)

    with open(resource_path("private_key.pem"), "wb") as f:
        f.write(private_pem)
    with open(resource_path("certificate.pem"), "wb") as f:
        f.write(cert_pem)

    return private_key, cert


def sign_file(file_path, private_key):
    """Sign a file and save the signature."""
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()

        signature = private_key.sign(
            file_content,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature).decode('utf-8')

        signature_file = f"{file_path}.sig"
        with open(signature_file, "w") as f:
            f.write(signature_b64)

        return signature, f"File signed. Signature saved as {signature_file}"
    except FileNotFoundError:
        return None, f"Error: File {file_path} not found."
    except Exception as e:
        return None, f"Error signing file: {str(e)}"

def verify_file(file_path, signature_file, cert):
    """Verify a file's signature using the certificate."""
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
        with open(signature_file, "r") as f:
            signature_b64 = f.read()
        signature = base64.b64decode(signature_b64)

        public_key = cert.public_key()
        try:
            public_key.verify(
                signature,
                file_content,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True, f"Signature for {file_path} is valid. Certificate verified."
        except InvalidSignature:
            return False, f"Signature for {file_path} is invalid."
    except FileNotFoundError:
        return False, f"Error: File {file_path} or {signature_file} not found."
    except Exception as e:
        return False, f"Error verifying signature: {str(e)}"

class HeaderWidget(QWidget):
    def __init__(self, title, subtitle, parent=None):
        super().__init__(parent)
        self.setObjectName("Header")
        self.setFixedHeight(180)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 20)
        self.title = QLabel(title)
        self.title.setObjectName("titleLabel")
        self.title.setAlignment(Qt.AlignCenter)
        self.subtitle = QLabel(subtitle)
        self.subtitle.setObjectName("subtitleLabel")
        self.subtitle.setAlignment(Qt.AlignCenter)
        layout.addStretch()
        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)
        layout.addStretch()

class CardWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("mainCard")
        self.setFrameShape(QFrame.StyledPanel)
        self.setFrameShadow(QFrame.Raised)

class CodeSignerUI(QMainWindow):
    instance = None

    def __init__(self):
        super().__init__()
        CodeSignerUI.instance = self
        self.setWindowTitle("DigiSign")
        self.setGeometry(100, 100, 900, 700)
        self.is_dark_theme = True
        self.dark_stylesheet = load_stylesheet("DARK")
        self.light_stylesheet = load_stylesheet("LIGHT")

        # Initialize status bar first
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Initializing...")

        # Load private key and certificate on startup
        self.load_keys_and_cert()

        self.setup_ui()
        self.update_ui_state()

    def setup_ui(self):
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.main_layout = QVBoxLayout(self.main_widget)
        self.main_layout.setContentsMargins(30, 20, 30, 30)
        self.main_layout.setSpacing(20)

        self.header = HeaderWidget("DigiSign", "Secure File Signing")
        self.main_layout.addWidget(self.header)

        self.card = CardWidget()
        self.card_layout = QVBoxLayout(self.card)
        self.card_layout.setContentsMargins(20, 20, 20, 20)
        self.card_layout.setSpacing(15)

        self.tabs = QTabWidget()
        self.setup_signing_tab()
        self.setup_certificate_tab()
        self.setup_rsa_tab()
        self.setup_public_key_tab()
        self.setup_private_key_tab()
        self.card_layout.addWidget(self.tabs)

        self.main_layout.addWidget(self.card)
        self.main_layout.addStretch()

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")

    def setup_signing_tab(self):
        self.signing_tab = QWidget()
        self.signing_layout = QVBoxLayout(self.signing_tab)
        self.signing_layout.setContentsMargins(10, 10, 10, 15)
        self.signing_layout.setSpacing(15)

        signing_label = QLabel("Code Signing Operations")
        signing_label.setObjectName("sectionLabel")
        self.signing_layout.addWidget(signing_label)

        file_select_layout = QHBoxLayout()
        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setStyleSheet("color: #7f8c8d; font-size: 14px;")
        self.select_file_btn = QPushButton("Select File")
        self.select_file_btn.setObjectName("secondary")
        self.select_file_btn.clicked.connect(self.select_file)
        file_select_layout.addWidget(self.file_path_label, 1)
        file_select_layout.addWidget(self.select_file_btn)
        self.signing_layout.addLayout(file_select_layout)

        btn_layout = QHBoxLayout()
        self.sign_btn = QPushButton("Sign File")
        self.sign_btn.clicked.connect(self.sign_file)
        self.verify_btn = QPushButton("Verify Signature")
        self.verify_btn.clicked.connect(self.verify_file)
        btn_layout.addWidget(self.sign_btn)
        btn_layout.addWidget(self.verify_btn)
        self.signing_layout.addLayout(btn_layout)

        theme_label = QLabel("Theme")
        theme_label.setStyleSheet("font-weight: 500;")
        self.signing_layout.addWidget(theme_label)

        self.theme_btn = QPushButton("Switch to Light Theme")
        self.theme_btn.setObjectName("secondary")
        self.theme_btn.clicked.connect(self.toggle_theme)
        self.signing_layout.addWidget(self.theme_btn, 0, Qt.AlignCenter)

        self.signing_layout.addStretch()
        self.tabs.addTab(self.signing_tab, "Code Signing")

    def setup_rsa_tab(self):
        self.rsa_tab = QWidget()
        self.rsa_layout = QVBoxLayout(self.rsa_tab)
        self.rsa_layout.setContentsMargins(10, 10, 10, 15)
        self.rsa_layout.setSpacing(15)

        # Message input section
        message_label = QLabel("Message")
        message_label.setObjectName("sectionLabel")
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Enter message to encrypt/decrypt")

        # Result section
        result_label = QLabel("Result")
        result_label.setObjectName("sectionLabel")
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)

        # Copy result button
        copy_result_btn = QPushButton("Copy Result")
        copy_result_btn.setObjectName("secondary")
        copy_result_btn.clicked.connect(self.copy_result)

        # Key management section
        # Private key controls
        private_key_layout = QHBoxLayout()
        self.private_key_path = QLabel("No private key loaded")
        load_private_key_btn = QPushButton("Load Private Key")
        load_private_key_btn.setObjectName("secondary")
        load_private_key_btn.clicked.connect(self.load_external_private_key)
        private_key_layout.addWidget(self.private_key_path)
        private_key_layout.addWidget(load_private_key_btn)

        # Public key controls
        public_key_layout = QHBoxLayout()
        self.public_key_path = QLabel("No public key loaded")
        load_public_key_btn = QPushButton("Load Public Key")
        load_public_key_btn.setObjectName("secondary")
        load_public_key_btn.clicked.connect(self.load_external_public_key)
        public_key_layout.addWidget(self.public_key_path)
        public_key_layout.addWidget(load_public_key_btn)

        # Action buttons
        action_layout = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt Message")
        encrypt_btn.clicked.connect(self.encrypt_message)
        decrypt_btn = QPushButton("Decrypt Message")
        decrypt_btn.clicked.connect(self.decrypt_message)
        action_layout.addWidget(encrypt_btn)
        action_layout.addWidget(decrypt_btn)

        # Add all components to layout
        self.rsa_layout.addWidget(message_label)
        self.rsa_layout.addWidget(self.message_input)
        self.rsa_layout.addWidget(result_label)
        self.rsa_layout.addWidget(self.result_output)
        self.rsa_layout.addWidget(copy_result_btn)
        self.rsa_layout.addLayout(private_key_layout)
        self.rsa_layout.addLayout(public_key_layout)
        self.rsa_layout.addLayout(action_layout)

        self.tabs.addTab(self.rsa_tab, "RSA Encryption")

    def copy_result(self):
        """Copy the result text to clipboard."""
        if self.result_output.toPlainText():
            QApplication.clipboard().setText(self.result_output.toPlainText())
            self.status_bar.showMessage("Result copied to clipboard")
        else:
            QMessageBox.warning(self, "Warning", "No result to copy")

    def decrypt_message(self):
        encrypted_message = self.message_input.toPlainText()
        if not encrypted_message:
            QMessageBox.warning(self, "Error", "No encrypted message to decrypt")
            return

        if not hasattr(self, 'rsa_private_key'):
            QMessageBox.warning(self, "Error", "Please load a private key first")
            return

        try:
            decrypted = self.rsa_private_key.decrypt(
                base64.b64decode(encrypted_message),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Update the result output instead of message input
            self.result_output.setText(decrypted.decode())
            self.status_bar.showMessage("Message decrypted successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")

    def load_keys_and_cert(self):
        """Load existing private key and certificate or generate new ones if they don't exist."""
        try:
            # Try to load existing private key and certificate
            with open(resource_path("private_key.pem"), "rb") as f:
                self.private_key = load_pem_private_key(f.read(), password=None)
            with open(resource_path("certificate.pem"), "rb") as f:
                self.cert = load_pem_x509_certificate(f.read())

            # Set RSA private key for encryption operations
            self.rsa_private_key = self.private_key
            self.status_bar.showMessage("Private key and certificate loaded successfully")
        except FileNotFoundError:
            # If either file doesn't exist, generate new ones
            try:
                self.private_key, self.cert = generate_self_signed_cert()
                # Set RSA private key for encryption operations
                self.rsa_private_key = self.private_key
                self.status_bar.showMessage("New private key and certificate generated successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to generate new keys: {str(e)}")
                self.private_key = None
                self.cert = None
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading keys: {str(e)}")
            self.private_key = None
            self.cert = None

    def setup_private_key_tab(self):
        self.private_key_tab = QWidget()
        self.private_key_layout = QVBoxLayout(self.private_key_tab)
        self.private_key_layout.setContentsMargins(10, 10, 10, 15)
        self.private_key_layout.setSpacing(15)

        # Private Key Management section
        private_key_label = QLabel("Private Key Management")
        private_key_label.setObjectName("sectionLabel")
        self.private_key_layout.addWidget(private_key_label)

        # Private Key Display
        key_label = QLabel("Private Key")
        key_label.setStyleSheet("font-weight: 500;")
        self.private_key_layout.addWidget(key_label)

        self.private_key_text = QTextEdit()
        self.private_key_text.setReadOnly(True)
        self.private_key_text.setMinimumHeight(200)
        if self.private_key:
            private_pem = self.private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ).decode('utf-8')
            self.private_key_text.setText(private_pem)
        self.private_key_layout.addWidget(self.private_key_text)

        # Warning label
        warning_label = QLabel("⚠️ Warning: Keep your private key secure and never share it!")
        warning_label.setStyleSheet("color: #ff6b6b; font-weight: 500;")
        self.private_key_layout.addWidget(warning_label)

        # Only keep export and copy buttons
        btn_layout = QHBoxLayout()
        export_btn = QPushButton("Export Private Key")
        export_btn.setObjectName("secondary")
        export_btn.clicked.connect(self.export_private_key)
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.setObjectName("secondary")
        copy_btn.clicked.connect(self.copy_private_key)
        btn_layout.addWidget(export_btn)
        btn_layout.addWidget(copy_btn)
        self.private_key_layout.addLayout(btn_layout)

        self.private_key_layout.addStretch()
        self.tabs.addTab(self.private_key_tab, "Private Key")

    def generate_new_key_pair(self):
        try:
            # Generate new RSA private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            # Get corresponding public key
            public_key = private_key.public_key()

            # Store the keys
            self.rsa_private_key = private_key
            self.rsa_public_key = public_key

            # Update private key display
            private_pem = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ).decode('utf-8')
            self.private_key_text.setText(private_pem)

            # Update public key display (if the tab exists)
            public_pem = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            if hasattr(self, 'pubkey_text'):
                self.pubkey_text.setText(public_pem)

            self.status_bar.showMessage("New key pair generated successfully")
            QMessageBox.information(self, "Success", "New RSA key pair generated successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate key pair: {str(e)}")

    def load_private_key_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Private Key",
            "",
            "PEM Files (*.pem);;All Files (*.*)"
        )
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    private_key_data = f.read()
                    self.rsa_private_key = load_pem_private_key(
                        private_key_data,
                        password=None
                    )
                    self.private_key_text.setText(private_key_data.decode('utf-8'))
                self.status_bar.showMessage(f"Private key loaded from {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load private key: {str(e)}")

    def export_private_key(self):
        if not hasattr(self, 'rsa_private_key'):
            QMessageBox.warning(self, "Warning", "No private key available to export")
            return

        # Show warning message
        response = QMessageBox.warning(
            self,
            "Security Warning",
            "Exporting private keys can be risky. Make sure to store it securely.\n"
            "Do you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if response == QMessageBox.Yes:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Private Key",
                "private_key.pem",
                "PEM Files (*.pem);;All Files (*.*)"
            )
            if file_path:
                try:
                    private_pem = self.rsa_private_key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=NoEncryption()
                    )
                    with open(file_path, "wb") as f:
                        f.write(private_pem)
                    self.status_bar.showMessage(f"Private key exported to {file_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to export private key: {str(e)}")

    def copy_private_key(self):
        if self.private_key_text.toPlainText():
            # Show warning message
            response = QMessageBox.warning(
                self,
                "Security Warning",
                "Copying private keys to clipboard can be risky. Make sure you're in a secure environment.\n"
                "Do you want to continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if response == QMessageBox.Yes:
                QApplication.clipboard().setText(self.private_key_text.toPlainText())
                self.status_bar.showMessage("Private key copied to clipboard")
        else:
            QMessageBox.warning(self, "Warning", "No private key available to copy")

    def generate_certificate(self):
        """Generate a new certificate using the existing private key."""
        try:
            if not self.private_key:
                # If no private key exists, generate both
                self.private_key, self.cert = generate_self_signed_cert()
                message = "New private key and certificate generated"
            else:
                # Use existing private key to generate new certificate
                public_key = self.private_key.public_key()
                subject = issuer = Name([
                    NameAttribute(ObjectIdentifier("2.5.4.3"), "Vedant Gandhi")
                ])
                cert = (
                    CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(issuer)
                    .public_key(public_key)
                    .serial_number(random_serial_number())
                    .not_valid_before(datetime.now(UTC))
                    .not_valid_after(datetime.now(UTC) + timedelta(days=365))
                    .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
                    .sign(self.private_key, hashes.SHA256())
                )

                # Save only the new certificate
                cert_pem = cert.public_bytes(Encoding.PEM)
                with open(resource_path("certificate.pem"), "wb") as f:
                    f.write(cert_pem)

                self.cert = cert
                message = "New certificate generated using existing private key"

            self.status_bar.showMessage(message)
            QMessageBox.information(self, "Success", message)
            self.update_ui_state()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate certificate: {str(e)}")
            self.status_bar.showMessage("Certificate generation failed")

    def setup_certificate_tab(self):
        self.cert_tab = QWidget()
        self.cert_layout = QVBoxLayout(self.cert_tab)
        self.cert_layout.setContentsMargins(10, 10, 10, 15)
        self.cert_layout.setSpacing(15)

        cert_label = QLabel("Certificate Management")
        cert_label.setObjectName("sectionLabel")
        self.cert_layout.addWidget(cert_label)

        self.gen_cert_btn = QPushButton("Generate New Certificate")
        self.gen_cert_btn.clicked.connect(self.generate_certificate)
        self.cert_layout.addWidget(self.gen_cert_btn)

        details_label = QLabel("Certificate Details")
        details_label.setStyleSheet("font-weight: 500;")
        self.cert_layout.addWidget(details_label)

        self.cert_details = QTextEdit()
        self.cert_details.setReadOnly(True)
        self.cert_details.setMinimumHeight(200)
        self.cert_layout.addWidget(self.cert_details)

        export_btn = QPushButton("Export Certificate")
        export_btn.setObjectName("secondary")
        export_btn.clicked.connect(self.export_certificate)
        self.cert_layout.addWidget(export_btn, 0, Qt.AlignCenter)

        self.cert_layout.addStretch()
        self.tabs.addTab(self.cert_tab, "Certificate")

    def setup_public_key_tab(self):
        self.pubkey_tab = QWidget()
        self.pubkey_layout = QVBoxLayout(self.pubkey_tab)
        self.pubkey_layout.setContentsMargins(10, 10, 10, 15)
        self.pubkey_layout.setSpacing(15)

        pubkey_label = QLabel("Public Key Management")
        pubkey_label.setObjectName("sectionLabel")
        self.pubkey_layout.addWidget(pubkey_label)

        key_label = QLabel("Public Key")
        key_label.setStyleSheet("font-weight: 500;")
        self.pubkey_layout.addWidget(key_label)

        self.pubkey_text = QTextEdit()
        self.pubkey_text.setReadOnly(True)
        self.pubkey_text.setMinimumHeight(200)
        self.pubkey_layout.addWidget(self.pubkey_text)

        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.setObjectName("secondary")
        copy_btn.clicked.connect(self.copy_public_key)
        export_btn = QPushButton("Export Public Key")
        export_btn.setObjectName("secondary")
        export_btn.clicked.connect(self.export_public_key)
        btn_layout.addWidget(copy_btn)
        btn_layout.addWidget(export_btn)
        self.pubkey_layout.addLayout(btn_layout)

        self.pubkey_layout.addStretch()
        self.tabs.addTab(self.pubkey_tab, "Public Key")

    def update_ui_state(self):
        has_cert = self.private_key is not None and self.cert is not None
        self.sign_btn.setEnabled(has_cert)
        self.verify_btn.setEnabled(has_cert)
        if has_cert:
            # Update certificate details
            cert_info = (
                f"Subject: {self.cert.subject.get_attributes_for_oid(ObjectIdentifier('2.5.4.3'))[0].value}\n"
                f"Issuer: {self.cert.issuer.get_attributes_for_oid(ObjectIdentifier('2.5.4.3'))[0].value}\n"
                f"Serial Number: {self.cert.serial_number}\n"
                f"Not Before: {self.cert.not_valid_before_utc}\n"
                f"Not After: {self.cert.not_valid_after_utc}"
            )
            self.cert_details.setText(cert_info)
            # Update public key
            public_key = self.cert.public_key()
            pubkey_pem = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            self.pubkey_text.setText(pubkey_pem)
        else:
            self.cert_details.setText("No certificate loaded. Generate one to view details.")
            self.pubkey_text.setText("No public key available. Generate a certificate first.")
            self.status_bar.showMessage("No certificate found. Please generate one.")

    def load_external_certificate(self):
        """Load an external certificate for verification."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Certificate",
            os.path.expanduser("~"),
            "Certificate Files (*.pem);;All Files (*.*)"
        )
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    self.external_cert = load_pem_x509_certificate(f.read())
                return True, "Certificate loaded successfully"
            except Exception as e:
                return False, f"Error loading certificate: {str(e)}"
        return False, "No certificate selected"

    def select_file(self):
        # Use home directory as starting point
        initial_dir = os.path.expanduser("~")
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File",
            initial_dir,  # Set initial directory
            "All Files (*.*)"
        )
        if file_path:
            self.file_path = file_path
            self.file_path_label.setText(os.path.basename(file_path))
            self.status_bar.showMessage(f"Selected file: {os.path.basename(file_path)}")
            if self.private_key and self.cert:
                self.sign_btn.setEnabled(True)
                self.verify_btn.setEnabled(True)
        else:
            self.file_path_label.setText("No file selected")
            self.status_bar.showMessage("File selection cancelled")
            self.sign_btn.setEnabled(False)
            self.verify_btn.setEnabled(False)

    def load_external_private_key(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Private Key",
            "",
            "PEM Files (*.pem);;All Files (*.*)"
        )
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    self.rsa_private_key = load_pem_private_key(
                        f.read(),
                        password=None
                    )
                self.private_key_path.setText(os.path.basename(file_path))
                self.status_bar.showMessage("Private key loaded successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load private key: {str(e)}")

    def load_external_public_key(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Public Key",
            "",
            "PEM Files (*.pem);;All Files (*.*)"
        )
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    self.rsa_public_key = serialization.load_pem_public_key(f.read())
                self.public_key_path.setText(os.path.basename(file_path))
                self.status_bar.showMessage("Public key loaded successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load public key: {str(e)}")

    def encrypt_message(self):
        message = self.message_input.toPlainText()
        if not message:
            QMessageBox.warning(self, "Error", "Please enter a message to encrypt")
            return

        if not hasattr(self, 'rsa_public_key'):
            QMessageBox.warning(self, "Error", "Please load a public key first")
            return

        try:
            encrypted = self.rsa_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.result_output.setText(base64.b64encode(encrypted).decode())
            self.status_bar.showMessage("Message encrypted successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")

    def generate_certificate(self):
        self.private_key, self.cert = generate_self_signed_cert()
        self.status_bar.showMessage("Certificate generated")
        QMessageBox.information(self, "Success", "Self-signed certificate generated: private_key.pem, certificate.pem")
        self.update_ui_state()

    def sign_file(self):
        if not hasattr(self, 'file_path') or not self.file_path:
            QMessageBox.warning(self, "Error", "Please select a file first.")
            self.status_bar.showMessage("Sign file failed: No file selected")
            return
        signature, message = sign_file(self.file_path, self.private_key)
        self.status_bar.showMessage(message)
        if signature:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Error", message)

    def verify_file(self):
        if not hasattr(self, 'file_path') or not self.file_path:
            QMessageBox.warning(self, "Error", "Please select a file first.")
            self.status_bar.showMessage("Verify signature failed: No file selected")
            return

        # Ask user whether to use current or external certificate
        use_external = QMessageBox.question(
            self,
            "Certificate Selection",
            "Do you want to verify using an external certificate?",
            QMessageBox.Yes | QMessageBox.No
        ) == QMessageBox.Yes

        if use_external:
            success, message = self.load_external_certificate()
            if not success:
                QMessageBox.warning(self, "Error", message)
                return
            cert_to_use = self.external_cert
        else:
            if not self.cert:
                QMessageBox.warning(self, "Error", "No local certificate available.")
                return
            cert_to_use = self.cert

        signature_file = f"{self.file_path}.sig"
        if not os.path.exists(signature_file):
            QMessageBox.warning(self, "Error", f"Signature file {signature_file} not found.")
            self.status_bar.showMessage("Verify signature failed: Signature file not found")
            return

        is_valid, message = verify_file(self.file_path, signature_file, cert_to_use)
        self.status_bar.showMessage(message)
        if is_valid:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Error", message)

    def export_certificate(self):
        if not self.cert:
            QMessageBox.warning(self, "Error", "No certificate available to export.")
            self.status_bar.showMessage("Export certificate failed: No certificate")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Certificate", "", "PEM Files (*.pem);;All Files (*.*)"
        )
        if file_path:
            try:
                with open(file_path, "wb") as f:
                    f.write(self.cert.public_bytes(Encoding.PEM))
                QMessageBox.information(self, "Success", f"Certificate exported to {file_path}")
                self.status_bar.showMessage("Certificate exported successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export certificate: {str(e)}")
                self.status_bar.showMessage("Export certificate failed")

    def copy_public_key(self):
        if not self.cert:
            QMessageBox.warning(self, "Error", "No public key available to copy.")
            self.status_bar.showMessage("Copy public key failed: No public key")
            return
        public_key = self.cert.public_key()
        pubkey_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        QApplication.clipboard().setText(pubkey_pem)
        QMessageBox.information(self, "Success", "Public key copied to clipboard")
        self.status_bar.showMessage("Public key copied to clipboard")

    def export_public_key(self):
        if not self.cert:
            QMessageBox.warning(self, "Error", "No public key available to export.")
            self.status_bar.showMessage("Export public key failed: No public key")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Public Key", "", "PEM Files (*.pem);;All Files (*.*)"
        )
        if file_path:
            try:
                public_key = self.cert.public_key()
                with open(file_path, "wb") as f:
                    f.write(public_key.public_bytes(
                        encoding=Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                QMessageBox.information(self, "Success", f"Public key exported to {file_path}")
                self.status_bar.showMessage("Public key exported successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export public key: {str(e)}")
                self.status_bar.showMessage("Export public key failed")

    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        app.setStyleSheet(self.dark_stylesheet if self.is_dark_theme else self.light_stylesheet)
        self.theme_btn.setText("Switch to Dark Theme" if not self.is_dark_theme else "Switch to Light Theme")
        self.status_bar.showMessage(f"Switched to {'Dark' if self.is_dark_theme else 'Light'} theme")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")  # Prevent native theme interference
    app.setStyleSheet(load_stylesheet("DARK"))  # Apply initial stylesheet
    window = CodeSignerUI()
    window.show()
    sys.exit(app.exec())
