import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import random
import string
import pyperclip

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator")
        self.master.geometry("400x350")

        self.label_length = ttk.Label(master, text="Password Length:")
        self.label_length.pack(pady=(10, 5))

        self.entry_length = ttk.Entry(master)
        self.entry_length.pack()

        self.label_complexity = ttk.Label(master, text="Password Complexity:")
        self.label_complexity.pack(pady=(10, 5))

        self.complexity_var = tk.StringVar()
        self.complexity_var.set("Medium")

        self.complexity_options = ttk.Combobox(master, textvariable=self.complexity_var,
                                                values=["Low", "Medium", "High"])
        self.complexity_options.pack()

        self.include_characters_var = tk.BooleanVar()
        self.include_characters_var.set(True)
        self.include_characters_checkbox = ttk.Checkbutton(master, text="Include characters",
                                                           variable=self.include_characters_var)
        self.include_characters_checkbox.pack()

        self.generate_button = ttk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.pack(pady=10)

        self.password_label = ttk.Label(master, text="")
        self.password_label.pack()

        self.copy_button = ttk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack(pady=10)

    def generate_password(self):
        password_length = self.entry_length.get()

        if not password_length.isdigit():
            messagebox.showerror("Error", "Please enter a valid number for password length.")
            return

        password_length = int(password_length)

        if password_length <= 0:
            messagebox.showerror("Error", "Password length must be greater than 0.")
            return

        complexity = self.complexity_var.get()
        include_characters = self.include_characters_var.get()
        password = self.generate_random_password(password_length, complexity, include_characters)
        self.password_label.config(text=password)

    def generate_random_password(self, length, complexity, include_characters=True):
        if complexity == "Low":
            if include_characters:
                characters = string.ascii_letters + string.digits
            else:
                characters = string.digits
        elif complexity == "Medium":
            if include_characters:
                characters = string.ascii_letters + string.digits + string.punctuation
            else:
                characters = string.digits + string.punctuation
        else:
            if include_characters:
                characters = string.ascii_letters + string.digits + string.punctuation + string.ascii_uppercase
            else:
                characters = string.digits + string.punctuation + string.ascii_uppercase

        password = ''.join(random.choice(characters) for i in range(length))
        return password

    def copy_to_clipboard(self):
        password = self.password_label.cget("text")
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard.")
        else:
            messagebox.showerror("Error", "No password generated yet.")

def main():
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
