import tkinter as tk
from tkinter import messagebox

S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

def aes_encrypt_block(plaintext_block, key):
    def sub_bytes(state):
        return [S_BOX[b] for b in state]

    def shift_rows(state):
        return state

    def mix_columns(state):
        return state

    def add_round_key(state, key):
        return [state[i] ^ key[i] for i in range(len(state))]

    def key_expansion(key):
        return key * 11

    state = list(plaintext_block)
    key_schedule = key_expansion(key)

    state = add_round_key(state, key_schedule[:16])

    for round in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, key_schedule[round * 16:(round + 1) * 16])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key_schedule[10 * 16:(10 + 1) * 16])

    return bytes(state)

def aes_decrypt_block(ciphertext_block, key):
    # Example implementation of AES decryption (inverse of encryption)
    def inv_sub_bytes(state):
        return [S_BOX.index(b) for b in state]

    def inv_shift_rows(state):
        return state

    def inv_mix_columns(state):
        return state

    def add_round_key(state, key):
        return [state[i] ^ key[i] for i in range(len(state))]

    def key_expansion(key):
        return key * 11

    state = list(ciphertext_block)
    key_schedule = key_expansion(key)

    state = add_round_key(state, key_schedule[10 * 16:(10 + 1) * 16])

    for round in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, key_schedule[round * 16:(round + 1) * 16])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, key_schedule[:16])

    return bytes(state)

def process_blocks(text_bytes, key_bytes, encrypt=True):
    block_size = 16
    processed_blocks = []

    for i in range(0, len(text_bytes), block_size):
        block = text_bytes[i:i+block_size]
        if len(block) < block_size:
            block += b'\x00' * (block_size - len(block))
        
        if encrypt:
            processed_block = aes_encrypt_block(block, key_bytes)
        else:
            processed_block = aes_decrypt_block(block, key_bytes).rstrip(b'\x00')

        processed_blocks.append(processed_block)

    return b''.join(processed_blocks)

def on_process():
    text = entry_text.get()
    key = entry_key.get()
    if len(key) != 16:
        messagebox.showerror("Invalid Key", "Key must be 16 characters long.")
        return

    key_bytes = key.encode('utf-8')

    if is_encrypted.get() == 0:  # Encryption
        plaintext_bytes = text.encode('utf-8')
        processed_bytes = process_blocks(plaintext_bytes, key_bytes, encrypt=True)
    else:  # Decryption
        try:
            ciphertext_bytes = bytes.fromhex(text)
        except ValueError:
            messagebox.showerror("Invalid Ciphertext", "Ciphertext must be in hex format.")
            return
        processed_bytes = process_blocks(ciphertext_bytes, key_bytes, encrypt=False)

    processed_text = processed_bytes.hex() if is_encrypted.get() == 0 else processed_bytes.decode('utf-8')
    entry_result.delete(0, tk.END)
    entry_result.insert(0, processed_text)

app = tk.Tk()
app.title("AES Encryption/Decryption")

frame = tk.Frame(app)
frame.pack(padx=10, pady=10)

label_text = tk.Label(frame, text="Text:")
label_text.grid(row=0, column=0, padx=5, pady=5)
entry_text = tk.Entry(frame, width=60)  
entry_text.grid(row=0, column=1, padx=5, pady=5)

label_key = tk.Label(frame, text="Key:")
label_key.grid(row=1, column=0, padx=5, pady=5)
entry_key = tk.Entry(frame, width=60, show="*")  
entry_key.grid(row=1, column=1, padx=5, pady=5)

is_encrypted = tk.IntVar()
radiobutton_encrypt = tk.Radiobutton(frame, text="Encrypt", variable=is_encrypted, value=0)
radiobutton_encrypt.grid(row=2, column=0, padx=5, pady=5)
radiobutton_encrypt.select()
radiobutton_decrypt = tk.Radiobutton(frame, text="Decrypt", variable=is_encrypted, value=1)
radiobutton_decrypt.grid(row=2, column=1, padx=5, pady=5)

button_process = tk.Button(frame, text="Process", command=on_process)
button_process.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

label_result = tk.Label(frame, text="Result:")
label_result.grid(row=4, column=0, padx=5, pady=5)
entry_result = tk.Entry(frame, width=60)  
entry_result.grid(row=4, column=1, padx=5, pady=5)

app.mainloop()
