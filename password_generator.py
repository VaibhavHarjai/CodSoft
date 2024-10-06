import tkinter as tk
from tkinter import messagebox
import random
import string

# Function to generate random password
def generate_password():
    password_length = length_var.get()

    if password_length.isdigit():
        password_length = int(password_length)
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(password_length))
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
    else:
        messagebox.showerror("Invalid input", "Please enter a valid number for password length")

# Function to copy password to clipboard
def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(password_entry.get())
    messagebox.showinfo("Copied", "Password copied to clipboard")

# Create GUI
root = tk.Tk()
root.title("Random Password Generator")
root.geometry('400x300')
root.configure(bg='#2c3e50')  # Dark background for neon effect

# Styling options
label_font = ("Helvetica", 12, "bold")
entry_font = ("Helvetica", 12)
button_font = ("Helvetica", 12, "bold")

# Title Label
title_label = tk.Label(root, text="Password Generator", font=("Helvetica", 16, "bold"), bg='#2c3e50', fg='#ffcc00')  # Neon yellow
title_label.pack(pady=10)

# Frame for password length input
length_frame = tk.Frame(root, bg='#2c3e50')
length_frame.pack(pady=10)

length_label = tk.Label(length_frame, text="Password Length:", font=label_font, bg='#2c3e50', fg='#ff007f')  # Neon pink
length_label.grid(row=0, column=0, padx=10)

length_var = tk.StringVar()
length_entry = tk.Entry(length_frame, textvariable=length_var, font=entry_font, width=10, bg='#ecf0f1')  # Light gray background for the input field
length_entry.grid(row=0, column=1)

# Frame for password display
password_frame = tk.Frame(root, bg='#2c3e50')
password_frame.pack(pady=10)

password_label = tk.Label(password_frame, text="Generated Password:", font=label_font, bg='#2c3e50', fg='#00ffcc')  # Neon cyan
password_label.grid(row=0, column=0, padx=10)

password_entry = tk.Entry(password_frame, font=entry_font, width=25, bg='#ecf0f1')
password_entry.grid(row=0, column=1)

# Frame for buttons
button_frame = tk.Frame(root, bg='#2c3e50')
button_frame.pack(pady=20)

generate_button = tk.Button(button_frame, text="Generate Password", font=button_font, bg='#ffcc00', fg='#2c3e50', command=generate_password)  # Neon yellow
generate_button.grid(row=0, column=0, padx=10)

copy_button = tk.Button(button_frame, text="Copy to Clipboard", font=button_font, bg='#00ffcc', fg='#2c3e50', command=copy_to_clipboard)  # Neon cyan
copy_button.grid(row=0, column=1, padx=10)

# Footer Label
footer_label = tk.Label(root, text="Copyright © 2024 Vaibhav Harjai", font=("Helvetica", 10), bg='#2c3e50', fg='white')
footer_label.pack(side="bottom", pady=10)

# Run the application
root.mainloop()