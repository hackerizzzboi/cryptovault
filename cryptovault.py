import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import json, os, base64, hashlib, secrets
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

class CryptoVaultPro:
    def __init__(self, root):
        self.root = root
        self.root.title("Dhiraj CryptoVault")
        self.root.geometry("900x650")
        
        # State
        self.current_key = None
        self.key_info = {}
        self.keystore = "crypto_keystore"
        os.makedirs(self.keystore, exist_ok=True)
        
        # Colors
        self.colors = {
            'bg': '#1a1a2e', 'card': '#16213e',
            'primary': '#0f4c75', 'success': '#4CAF50',
            'warning': '#FF9800', 'danger': '#f44336',
            'text': '#ffffff'
        }
        self.root.configure(bg=self.colors['bg'])
        
        self.setup_ui()
        self.center_window()
    
    def setup_ui(self):
        """Modern tabbed interface"""
        # Title
        title_frame = tk.Frame(self.root, bg=self.colors['primary'])
        title_frame.pack(fill='x')
        tk.Label(title_frame, text="🔐 CRYPTOVAULT PRO", font=('Arial', 24, 'bold'),
                fg='white', bg=self.colors['primary']).pack(pady=15)
        
        # Tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        tabs = [
            ("🏠 Dashboard", self.create_dashboard),
            ("🔑 Keys", self.create_keys_tab),
            ("🔒 Encrypt", self.create_encrypt_tab),
            ("📝 Sign", self.create_sign_tab),
            ("📊 Use Cases", self.create_usecases_tab)
        ]
        
        for tab_name, creator in tabs:
            tab = ttk.Frame(self.notebook)
            self.notebook.add(tab, text=tab_name)
            creator(tab)
    
    def create_dashboard(self, tab):
        """Modern dashboard"""
        # Stats
        stats_frame = tk.Frame(tab, bg=self.colors['bg'])
        stats_frame.pack(fill='x', pady=20)
        
        stats = [
            ("🔑", "Keys", "0"),
            ("🔒", "Encrypted", "0"),
            ("📝", "Signed", "0"),
            ("✅", "Verified", "0")
        ]
        
        for i, (icon, label, value) in enumerate(stats):
            card = tk.Frame(stats_frame, bg=self.colors['card'], relief=tk.RAISED, bd=2)
            card.pack(side=tk.LEFT, padx=10, ipadx=20, ipady=15)
            tk.Label(card, text=icon, font=('Arial', 20), bg=self.colors['card'], fg='white').pack()
            tk.Label(card, text=label, font=('Arial', 10), bg=self.colors['card'], fg='#aaa').pack()
            tk.Label(card, text=value, font=('Arial', 16, 'bold'), bg=self.colors['card'], fg='white').pack()
        
        # Quick actions
        actions = tk.LabelFrame(tab, text="Quick Actions", font=('Arial', 12, 'bold'),
                              bg=self.colors['bg'], fg='white')
        actions.pack(fill='x', padx=20, pady=20)
        
        btn_frame = tk.Frame(actions, bg=self.colors['bg'])
        btn_frame.pack(pady=10)
        
        quick_actions = [
            ("Generate RSA Key", lambda: self.generate_key('RSA')),
            ("Encrypt Text", lambda: self.notebook.select(2)),
            ("Sign Document", lambda: self.notebook.select(3)),
            ("Verify File", self.verify_quick)
        ]
        
        for text, cmd in quick_actions:
            tk.Button(btn_frame, text=text, command=cmd, bg=self.colors['primary'],
                     fg='white', padx=15, pady=8).pack(side=tk.LEFT, padx=5)
    
    def create_keys_tab(self, tab):
        """Key management with auto-load"""
        # Generation
        gen_frame = tk.LabelFrame(tab, text="Generate Keys", font=('Arial', 12, 'bold'),
                                bg=self.colors['bg'], fg='white')
        gen_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(gen_frame, text="Key Name:", bg=self.colors['bg'], fg='white').grid(row=0, column=0, padx=10, pady=10)
        self.key_name = tk.Entry(gen_frame, width=30)
        self.key_name.grid(row=0, column=1, padx=10, pady=10)
        self.key_name.insert(0, f"key_{datetime.now().strftime('%H%M%S')}")
        
        tk.Label(gen_frame, text="Algorithm:", bg=self.colors['bg'], fg='white').grid(row=1, column=0, padx=10)
        self.algo = tk.StringVar(value="RSA")
        tk.Radiobutton(gen_frame, text="RSA 2048", variable=self.algo, value="RSA",
                      bg=self.colors['bg'], fg='white', selectcolor=self.colors['bg']).grid(row=1, column=1, sticky='w')
        tk.Radiobutton(gen_frame, text="ECC P-256", variable=self.algo, value="ECC",
                      bg=self.colors['bg'], fg='white', selectcolor=self.colors['bg']).grid(row=1, column=2, sticky='w')
        
        tk.Button(gen_frame, text="Generate & Auto-Load", command=self.generate_and_load,
                 bg=self.colors['success'], fg='white', padx=20, pady=5).grid(row=2, column=0, columnspan=3, pady=15)
        
        # Current key display
        key_frame = tk.LabelFrame(tab, text="Loaded Key", font=('Arial', 12, 'bold'),
                                bg=self.colors['bg'], fg='white')
        key_frame.pack(fill='x', padx=10, pady=10)
        
        self.key_display = tk.Label(key_frame, text="No key loaded", bg=self.colors['card'],
                                   fg='#aaa', padx=10, pady=10, justify=tk.LEFT)
        self.key_display.pack(fill='x', padx=10, pady=10)
    
    def create_encrypt_tab(self, tab):
        """Encryption/Decryption tab"""
        # Mode selector
        mode_frame = tk.Frame(tab, bg=self.colors['bg'])
        mode_frame.pack(fill='x', pady=10)
        
        self.mode = tk.StringVar(value="encrypt")
        tk.Radiobutton(mode_frame, text="🔒 Encrypt", variable=self.mode, value="encrypt",
                      bg=self.colors['bg'], fg='white', selectcolor=self.colors['bg'],
                      command=self.update_mode).pack(side=tk.LEFT, padx=20)
        tk.Radiobutton(mode_frame, text="🔓 Decrypt", variable=self.mode, value="decrypt",
                      bg=self.colors['bg'], fg='white', selectcolor=self.colors['bg'],
                      command=self.update_mode).pack(side=tk.LEFT)
        
        # Input
        input_frame = tk.LabelFrame(tab, text="Input", font=('Arial', 12, 'bold'),
                                  bg=self.colors['bg'], fg='white')
        input_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, height=8, font=('Arial', 10))
        self.input_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.input_text.insert('1.0', "Enter text to encrypt...")
        
        # Action buttons
        btn_frame = tk.Frame(tab, bg=self.colors['bg'])
        btn_frame.pack(fill='x', pady=10)
        
        self.action_btn = tk.Button(btn_frame, text="🔒 Encrypt", command=self.perform_crypto,
                                   bg=self.colors['primary'], fg='white', font=('Arial', 11),
                                   padx=30, pady=10)
        self.action_btn.pack(side=tk.LEFT, padx=20)
        
        tk.Button(btn_frame, text="📋 Copy", command=self.copy_result,
                 bg=self.colors['warning'], fg='white', padx=20, pady=8).pack(side=tk.LEFT, padx=5)
        
        # Output
        output_frame = tk.LabelFrame(tab, text="Result", font=('Arial', 12, 'bold'),
                                   bg=self.colors['bg'], fg='white')
        output_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=8, font=('Courier', 9))
        self.output_text.pack(fill='both', expand=True, padx=10, pady=10)
    
    def create_sign_tab(self, tab):
        """Digital signatures"""
        # File selection
        file_frame = tk.LabelFrame(tab, text="File Operations", font=('Arial', 12, 'bold'),
                                 bg=self.colors['bg'], fg='white')
        file_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(file_frame, text="File:", bg=self.colors['bg'], fg='white').grid(row=0, column=0, padx=10, pady=10)
        self.file_path = tk.Entry(file_frame, width=40)
        self.file_path.grid(row=0, column=1, padx=10, pady=10)
        tk.Button(file_frame, text="Browse", command=self.browse_file,
                 bg=self.colors['primary'], fg='white').grid(row=0, column=2, padx=10)
        
        # Actions
        btn_frame = tk.Frame(file_frame, bg=self.colors['bg'])
        btn_frame.grid(row=1, column=0, columnspan=3, pady=10)
        
        tk.Button(btn_frame, text="📤 Sign File", command=self.sign_file,
                 bg=self.colors['success'], fg='white', padx=20, pady=8).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="✅ Verify Signature", command=self.verify_file,
                 bg=self.colors['warning'], fg='white', padx=20, pady=8).pack(side=tk.LEFT, padx=5)
        
        # Result
        result_frame = tk.LabelFrame(tab, text="Signature Details", font=('Arial', 12, 'bold'),
                                   bg=self.colors['bg'], fg='white')
        result_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.sig_result = scrolledtext.ScrolledText(result_frame, height=10, font=('Courier', 9))
        self.sig_result.pack(fill='both', expand=True, padx=10, pady=10)
    
    def create_usecases_tab(self, tab):
        """Use cases with demonstrations"""
        uc_frame = tk.Frame(tab, bg=self.colors['bg'])
        uc_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        use_cases = [
            ("📄 Secure Documents", "Digitally sign contracts and legal documents"),
            ("📧 Encrypted Email", "End-to-end encrypted communication"),
            ("💻 Code Signing", "Verify software integrity and authenticity")
        ]
        
        for i, (title, desc) in enumerate(use_cases):
            frame = tk.Frame(uc_frame, bg=self.colors['card'], relief=tk.RAISED, bd=1)
            frame.pack(fill='x', pady=10, padx=10)
            
            tk.Label(frame, text=title, font=('Arial', 14, 'bold'),
                    bg=self.colors['card'], fg='white').pack(anchor='w', padx=10, pady=(10,5))
            tk.Label(frame, text=desc, font=('Arial', 10),
                    bg=self.colors['card'], fg='#ccc', justify=tk.LEFT).pack(anchor='w', padx=10, pady=(0,10))
            
            tk.Button(frame, text="Demo", command=lambda t=title: self.demo_use_case(t),
                     bg=self.colors['primary'], fg='white').pack(pady=(0,10))
    
    # ========== CORE CRYPTO FUNCTIONS ==========
    
    def generate_and_load(self):
        """Generate and auto-load keys"""
        name = self.key_name.get().strip()
        if not name:
            messagebox.showerror("Error", "Enter key name")
            return
        
        try:
            if self.algo.get() == "RSA":
                self.current_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
            else:
                self.current_key = ec.generate_private_key(
                    ec.SECP256R1(),
                    default_backend()
                )
            
            # Save metadata
            self.key_info = {
                'name': name,
                'algo': self.algo.get(),
                'created': datetime.now().isoformat(),
                'public_key': self.current_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            }
            
            # Save to file
            with open(f"{self.keystore}/{name}.json", 'w') as f:
                json.dump(self.key_info, f, indent=2)
            
            # Update display
            self.key_display.config(
                text=f"✅ {self.algo.get()} Key: {name}\n"
                     f"Created: {datetime.now().strftime('%H:%M:%S')}\n"
                     f"Ready for use",
                fg=self.colors['success']
            )
            
            messagebox.showinfo("Success", f"{self.algo.get()} key generated and loaded!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
    
    def update_mode(self):
        """Update encryption/decryption mode"""
        if self.mode.get() == "encrypt":
            self.action_btn.config(text="🔒 Encrypt", bg=self.colors['primary'])
            self.input_text.delete('1.0', tk.END)
            self.input_text.insert('1.0', "Enter text to encrypt...")
        else:
            self.action_btn.config(text="🔓 Decrypt", bg=self.colors['warning'])
            self.input_text.delete('1.0', tk.END)
            self.input_text.insert('1.0', "Paste encrypted JSON here...")
    
    def perform_crypto(self):
        """Perform encryption or decryption"""
        if not self.current_key:
            messagebox.showerror("Error", "Generate or load a key first!")
            return
        
        data = self.input_text.get('1.0', tk.END).strip()
        if not data:
            messagebox.showerror("Error", "Enter some data!")
            return
        
        try:
            if self.mode.get() == "encrypt":
                # Hybrid encryption
                aes_key = secrets.token_bytes(32)
                iv = secrets.token_bytes(16)
                
                # AES encryption
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), default_backend())
                encryptor = cipher.encryptor()
                padder = sym_padding.PKCS7(128).padder()
                padded = padder.update(data.encode()) + padder.finalize()
                encrypted = encryptor.update(padded) + encryptor.finalize()
                
                # RSA encrypt AES key
                encrypted_key = self.current_key.public_key().encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Create package
                package = {
                    'encrypted_key': base64.b64encode(encrypted_key).decode(),
                    'iv': base64.b64encode(iv).decode(),
                    'data': base64.b64encode(encrypted).decode(),
                    'timestamp': datetime.now().isoformat(),
                    'algo': 'RSA-AES-256-CBC'
                }
                
                self.output_text.delete('1.0', tk.END)
                self.output_text.insert('1.0', json.dumps(package, indent=2))
                messagebox.showinfo("Success", "Encryption complete!")
                
            else:
                # Decryption
                package = json.loads(data)
                encrypted_key = base64.b64decode(package['encrypted_key'])
                iv = base64.b64decode(package['iv'])
                encrypted_data = base64.b64decode(package['data'])
                
                # Decrypt AES key
                aes_key = self.current_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decrypt data
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), default_backend())
                decryptor = cipher.decryptor()
                padded = decryptor.update(encrypted_data) + decryptor.finalize()
                
                unpadder = sym_padding.PKCS7(128).unpadder()
                decrypted = unpadder.update(padded) + unpadder.finalize()
                
                self.output_text.delete('1.0', tk.END)
                self.output_text.insert('1.0', decrypted.decode())
                messagebox.showinfo("Success", "Decryption complete!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {str(e)}")
    
    def browse_file(self):
        """Browse for file"""
        path = filedialog.askopenfilename()
        if path:
            self.file_path.delete(0, tk.END)
            self.file_path.insert(0, path)
    
    def sign_file(self):
        """Sign a file"""
        if not self.current_key:
            messagebox.showerror("Error", "Load a key first!")
            return
        
        path = self.file_path.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Select a valid file!")
            return
        
        try:
            with open(path, 'rb') as f:
                data = f.read()
            
            # Create signature
            signature = self.current_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Save signature
            sig_path = path + '.sig'
            with open(sig_path, 'wb') as f:
                f.write(signature)
            
            # Create info file
            info = {
                'file': os.path.basename(path),
                'signature': signature.hex(),
                'hash': hashlib.sha256(data).hexdigest(),
                'timestamp': datetime.now().isoformat(),
                'algorithm': 'SHA256'
            }
            
            with open(path + '.sig.json', 'w') as f:
                json.dump(info, f, indent=2)
            
            self.sig_result.delete('1.0', tk.END)
            self.sig_result.insert('1.0', f"✅ File signed successfully!\n\n"
                                        f"Signature saved to: {sig_path}\n"
                                        f"File hash: {info['hash'][:16]}...")
            
            messagebox.showinfo("Success", "File signed!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Signing failed: {str(e)}")
    
    def verify_file(self):
        """Verify file signature"""
        if not self.current_key:
            messagebox.showerror("Error", "Load a key first!")
            return
        
        path = self.file_path.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Select a valid file!")
            return
        
        # Ask for signature
        sig_file = filedialog.askopenfilename(title="Select signature file")
        if not sig_file:
            return
        
        try:
            with open(path, 'rb') as f:
                data = f.read()
            with open(sig_file, 'rb') as f:
                signature = f.read()
            
            # Verify
            self.current_key.public_key().verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            self.sig_result.delete('1.0', tk.END)
            self.sig_result.insert('1.0', "✅ SIGNATURE VALID\n\n"
                                        "The file has NOT been tampered with.\n"
                                        "Signature verified successfully!")
            
            messagebox.showinfo("Success", "Signature is valid!")
            
        except Exception as e:
            self.sig_result.delete('1.0', tk.END)
            self.sig_result.insert('1.0', f"❌ SIGNATURE INVALID\n\n"
                                        f"The file may have been modified.\n"
                                        f"Error: {str(e)}")
            messagebox.showerror("Error", "Signature verification failed!")
    
    def copy_result(self):
        """Copy result to clipboard"""
        result = self.output_text.get('1.0', tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Copied", "Result copied to clipboard!")
    
    def verify_quick(self):
        """Quick verify"""
        self.notebook.select(3)
        messagebox.showinfo("Info", "Select a file and signature to verify")
    
    def demo_use_case(self, title):
        """Demo a use case"""
        demos = {
            "📄 Secure Documents": "1. Generate digital certificate\n2. Sign PDF/DOCX file\n3. Verify integrity\n4. Maintain audit trail",
            "📧 Encrypted Email": "1. Exchange public keys\n2. Encrypt message\n3. Send securely\n4. Recipient decrypts",
            "💻 Code Signing": "1. Sign executable\n2. Distribute software\n3. Users verify\n4. Prevent tampering"
        }
        
        demo_win = tk.Toplevel(self.root)
        demo_win.title(f"Demo: {title}")
        demo_win.geometry("500x300")
        demo_win.configure(bg=self.colors['bg'])
        
        tk.Label(demo_win, text=title, font=('Arial', 16, 'bold'),
                bg=self.colors['bg'], fg='white').pack(pady=20)
        
        tk.Label(demo_win, text=demos[title], font=('Arial', 11),
                bg=self.colors['bg'], fg='#ccc', justify=tk.LEFT).pack(padx=30, pady=20)
        
        tk.Button(demo_win, text="Try Now", command=lambda: self.notebook.select(1),
                 bg=self.colors['primary'], fg='white', padx=20, pady=10).pack(pady=20)
    
    def center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        w, h = self.root.winfo_width(), self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

# ========== MAIN ==========

def main():
    root = tk.Tk()
    app = CryptoVaultPro(root)
    root.mainloop()

if __name__ == "__main__":
    print("🚀 Dhiraj CryptoVault Pro - Advanced PKI Tool")
    print("📚 For Softwarica College - ST6051CEM")
    print("=" * 50)
    main()