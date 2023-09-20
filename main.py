from tkinter import *
from PIL import ImageTk, Image
from tkinter import messagebox
import base64

window = Tk()
window.title("Secret Notes")
window.config(padx=30, pady=30)


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


# UI
img = ImageTk.PhotoImage(Image.open("topsecret.png"))
Label(image=img).pack()
title_text = Label(text="Enter your title", font=("Arial", 14))
title_text.pack()
title_text_entry = Entry(width=30)
title_text_entry.pack()

secret_text = Label(text="Enter your secret", font=("Arial", 14))
secret_text.pack()
secret_text_entry = Text(width=40, height=20)
secret_text_entry.pack()

key_text = Label(text="Enter master key", font=("Arial", 14))
key_text.pack()
key_text_entry = Entry()
key_text_entry.pack()


def create_txt():
    if not title_text_entry.get() or not secret_text_entry.get("1.0", END) or not key_text_entry.get():
        messagebox.showwarning("Warning", "Please enter all info.")
        return
    else:
        tite = title_text_entry.get()
        message = secret_text_entry.get("1.0", END)
        master_secret = key_text_entry.get()
        message_encrypted = encode(master_secret, message)
        try:
            with open("mysecret.txt", "a") as data:
                data.write(f"\n{tite}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data:
                data.write(f"\n{tite}\n{message_encrypted}")
        finally:
            title_text_entry.delete(0, END)
            secret_text_entry.delete("1.0", END)
            key_text_entry.delete(0, END)


def decrypt_notes():
    message_encryped = secret_text_entry.get("1.0", END)
    master_secret = key_text_entry.get()

    if not secret_text_entry.get("1.0", END) or not key_text_entry.get():
        messagebox.showwarning("Warning", "Please enter all info.")
        return

    else:
        try:
            decrypted_message = decode(master_secret, message_encryped)
            secret_text_entry.delete("1.0", END)
            secret_text_entry.insert("1.0", decrypted_message)
        except:
            messagebox.showwarning("Warning", "Please enter encrypted text!")


save_button = Button(text="Save & Encrypt", font=("Arial", 10), command=create_txt)
save_button.pack()

decrypt_button = Button(text="Decrypt", font=("Arial", 10), command=decrypt_notes)
decrypt_button.pack()

window.mainloop()
