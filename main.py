import tkinter
import base64
from tkinter import messagebox
from tkinter import PhotoImage

window = tkinter.Tk()
window.title("Secret Notes")
window.config(padx=50,pady=10)

# Load the image
logo = PhotoImage(file="newversionpic.png")
photo_upload = tkinter.Label(image=logo)
photo_upload.pack()



enter_your_title = tkinter.Label(text="Enter Your Title",font=("Arial",15,"bold"))
enter_your_title.pack()

enter_your_title_entry = tkinter.Entry(width=40)
enter_your_title_entry.pack()


enter_your_secret_title=tkinter.Label(text="Enter Your Secret",font=("Arial",15,"bold"))
enter_your_secret_title.pack()


enter_your_secret_entry = tkinter.Text(width=30,height=8)
enter_your_secret_entry.pack()


enter_your_masterkey = tkinter.Label(text="Enter Master Key",font=("Arial",15,"bold"))
enter_your_masterkey.pack()


enter_your_masterkey_entry = tkinter.Entry(width=40)
enter_your_masterkey_entry.pack()


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



def save_and_encrypt():
    title = enter_your_title_entry.get()
    secret = enter_your_secret_entry.get(1.0 ,1000.1000)
    masterkey = enter_your_masterkey_entry.get()

    if len(title) == 0 or len(secret) == 0 or len(masterkey) == 0:
        messagebox.showinfo(title="Error!" , message="Please enter all info.")
    else:
        message_encrypted = encode(masterkey,secret)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            enter_your_title_entry.delete(0,1000)
            enter_your_secret_entry.delete("1.0",1000.1000)
            enter_your_masterkey_entry.delete(0,1000)


def decrypt():
    message_encrypted = enter_your_secret_entry.get(1.0 ,1000.1000)
    master_secret = enter_your_masterkey_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!" , message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            enter_your_secret_entry.delete(1.0,1000.1000)
            enter_your_secret_entry.insert(1.0 ,decrypted_message)
        except:
            messagebox.showinfo(title="Error!",message="Please make sure of encrypted info.")



save_and_encrypt_button = tkinter.Button(text="Save & Encrypt",command=save_and_encrypt)
save_and_encrypt_button.pack()

decrypt_button = tkinter.Button(text="Decrypt",command=decrypt)
decrypt_button.pack()


window.mainloop()
