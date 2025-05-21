import os
import random
import time
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter

# Constants
KEY_SIZE = 16  # AES-128 key size (16 bytes)
BLOCK_SIZE = AES.block_size # AES block size (16 bytes)
OUTPUT_DIR = 'output' # Directory to save results

def create_output_folder():
  if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def save_image_from_data(data, mode, size, output_path):
    img = Image.frombytes(mode, size, data)
    img.save(output_path)
  
def corrupt_data(data: bytes, num_bits: int) -> bytes:
    data_list = list(data)
    data_len_bits = len(data_list) * 8
    
    if num_bits > data_len_bits:
        num_bits = data_len_bits # Cap the number of bits to flip

    indices_to_flip = random.sample(range(data_len_bits), num_bits)

    for bit_index in indices_to_flip:
        byte_index = bit_index // 8
        bit_in_byte_index = bit_index % 8
        # Flip the bit using XOR
        data_list[byte_index] ^= (1 << bit_in_byte_index)

    return bytes(data_list)

# Task 1: Encryption/Decryption Functions

# ECB Mode
def encrypt_ecb(key, plaintext):
  cipher = AES.new(key, AES.MODE_ECB)
  padded_plaintext = pad(plaintext, BLOCK_SIZE)
  ciphertext = cipher.encrypt(padded_plaintext)
  return ciphertext

def decrypt_ecb(key, ciphertext):
  cipher = AES.new(key, AES.MODE_ECB)
  decrypted_padded = cipher.decrypt(ciphertext)
  plaintext = unpad(decrypted_padded, BLOCK_SIZE)
  return plaintext

# CBC Mode
def encrypt_cbc(key, plaintext):
  iv = get_random_bytes(BLOCK_SIZE)
  cipher = AES.new(key, AES.MODE_CBC, iv=iv)
  padded_plaintext = pad(plaintext, BLOCK_SIZE)
  ciphertext = cipher.encrypt(padded_plaintext)
  return iv + ciphertext # Prepend IV for decryption

def decrypt_cbc(key, iv_ciphertext):
  iv = iv_ciphertext[:BLOCK_SIZE]
  ciphertext = iv_ciphertext[BLOCK_SIZE:]
  cipher = AES.new(key, AES.MODE_CBC, iv=iv)
  decrypted_padded = cipher.decrypt(ciphertext)
  plaintext = unpad(decrypted_padded, BLOCK_SIZE)
  return plaintext

# OFB Mode
def encrypt_ofb(key, plaintext):
  iv = get_random_bytes(BLOCK_SIZE)
  cipher = AES.new(key, AES.MODE_OFB, iv=iv)
  ciphertext = cipher.encrypt(plaintext)
  return iv + ciphertext

def decrypt_ofb(key, iv_ciphertext):
  iv = iv_ciphertext[:BLOCK_SIZE]
  ciphertext = iv_ciphertext[BLOCK_SIZE:]
  cipher = AES.new(key, AES.MODE_OFB, iv=iv) # Use the original IV
  plaintext = cipher.decrypt(ciphertext) # Decryption is the same as encryption
  return plaintext

# CTR Mode
def encrypt_ctr(key, plaintext):
  # Nonce should be unique per message encrypted with the same key
  nonce = get_random_bytes(BLOCK_SIZE // 2) # e.g., 8 bytes nonce
  ctr = Counter.new(nbits=BLOCK_SIZE * 8 // 2, initial_value=0, prefix=nonce) # 8 byte counter
  cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
  ciphertext = cipher.encrypt(plaintext)
  return nonce + ciphertext # Prepend nonce for decryption

def decrypt_ctr(key, nonce_ciphertext):
  nonce = nonce_ciphertext[:BLOCK_SIZE // 2]
  ciphertext = nonce_ciphertext[BLOCK_SIZE // 2:]
  ctr = Counter.new(nbits=BLOCK_SIZE * 8 // 2, initial_value=0, prefix=nonce) # Recreate the same counter
  cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
  plaintext = cipher.decrypt(ciphertext) # Decryption is the same as encryption
  return plaintext

# Main function to run the tasks
if __name__ == "__main__":
  create_output_folder()

  # Load Image
  try:
    img = Image.open('test_image.bmp')
    img_mode = img.mode
    img_size = img.size
    # Pillow handles BMP header reading/writing during open/save.
    # We just need the raw pixel data.
    original_pixel_data = img.tobytes()
  except FileNotFoundError:
    print(f"Whoops no image found :(")
    exit(1)
  except Exception as e:
    print(f"Error loading image: {e}")
    exit(1)

  # Generate a random AES key
  key = get_random_bytes(KEY_SIZE)
  print(f"Generated AES-128 Key (hex): {key.hex()}")

  modes = {
      "ecb": (encrypt_ecb, decrypt_ecb),
      "cbc": (encrypt_cbc, decrypt_cbc),
      "ofb": (encrypt_ofb, decrypt_ofb),
      "ctr": (encrypt_ctr, decrypt_ctr)
  }

  encrypted_data_map = {} # To store encrypted data for corruption test

  # Task 2: Encryption/Decryption
  for mode_name, (encrypt_func, decrypt_func) in modes.items():
    print(f"\n{mode_name.upper()}")

    # Time encryption (average of 5 runs)
    total_encrypt_time = 0
    for _ in range(5):
        start_time = time.time()
        encrypted_data = encrypt_func(key, original_pixel_data)
        end_time = time.time()
        total_encrypt_time += (end_time - start_time)
    
    avg_encrypt_time = total_encrypt_time / 5
    print(f"Average encryption time ({mode_name}): {avg_encrypt_time:.6f} seconds")
    
    encrypted_data_map[mode_name] = encrypted_data # Store for Task 3
    encrypted_path = os.path.join(OUTPUT_DIR, f"{mode_name}_encrypted.bmp")
    print("Encrypting")
    
    # Extract the data part relevant for saving (without IV/nonce for CBC/OFB/CTR for image saving part)
    saveable_encrypted_data = encrypted_data
    if mode_name == "cbc":
        saveable_encrypted_data = encrypted_data[BLOCK_SIZE:] # Skip IV
    elif mode_name == "ofb":
        saveable_encrypted_data = encrypted_data[BLOCK_SIZE:] # Skip IV
    elif mode_name == "ctr":
        saveable_encrypted_data = encrypted_data[BLOCK_SIZE // 2:] # Skip Nonce
  
    save_image_from_data(saveable_encrypted_data, img_mode, img_size, encrypted_path)
    print("Encrypted image saved.")

    # Time decryption (average of 5 runs)
    total_decrypt_time = 0
    for _ in range(5):
        start_time = time.time()
        decrypted_data = decrypt_func(key, encrypted_data)
        end_time = time.time()
        total_decrypt_time += (end_time - start_time)
    
    avg_decrypt_time = total_decrypt_time / 5
    print(f"Average decryption time ({mode_name}): {avg_decrypt_time:.6f} seconds")
    
    decrypted_path = os.path.join(OUTPUT_DIR, f"{mode_name}_decrypted.bmp")
    print("Decrypting")

    # Save Decrypted Image
    save_image_from_data(decrypted_data, img_mode, img_size, decrypted_path)
    print("Decrypted image saved.")

  # Task 3: Corruption
  for mode_name, (encrypt_func, decrypt_func) in modes.items():
      print(f"\nCorrupt {mode_name.upper()}")
      
      encrypted_data = encrypted_data_map[mode_name]
      
      # Corrupt the *entire* encrypted data (including IV/nonce if present)
      corrupted_encrypted_data = corrupt_data(encrypted_data, 200)
      
      # Attempt Decryption of corrupted data
      corrupted_decrypted_data = decrypt_func(key, corrupted_encrypted_data)
      corrupted_decrypted_path = os.path.join(OUTPUT_DIR, f"{mode_name}_corrupted_decrypted.bmp")
      print("Decrypting (corrupt)")

      # Save Corrupted Decrypted Image
      save_image_from_data(corrupted_decrypted_data, img_mode, img_size, corrupted_decrypted_path)
      print("Decrypted image saved (corrupted).")

  print("Done!")