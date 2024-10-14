
# import os
# import hashlib
# from django.shortcuts import render, redirect
# from django.core.mail import send_mail
# from django.contrib.auth import logout, authenticate, login
# from django.contrib.auth.models import User
# from django.contrib import messages
# import random
# from cryptography.fernet import Fernet
# from .models import OTP, EncryptedBlock  # Import the EncryptedBlock model
# from django.conf import settings
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, NoEncryption

# # Get the encryption key from settings or environment variable
# cipher = Fernet(settings.FERNET_KEY.encode())

# # Generate RSA private and public key pair
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# public_key = private_key.public_key()

# # Hash generation function (for the 'data' field)
# def generate_hash(data):
#     return hashlib.sha256(data.encode()).hexdigest()

# # Digital signature generation function (for the 'data' field)
# def generate_signature(data):
#     try:
#         # Use the private key to sign the data
#         signature = private_key.sign(
#             data.encode(),
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),
#                 salt_length=padding.PSS.MAX_LENGTH
#             ),
#             hashes.SHA256()
#         )
#         return signature.hex()  # Convert to hex for easy display
#     except Exception as e:
#         print(f"Error generating signature: {e}")
#         return None

# # Login view
# def login_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             login(request, user)
#             return redirect('block_create')
#         else:
#             messages.error(request, "Invalid username or password.")
#     return render(request, 'login1.html')

# # Block Create View with Encryption, Hashing, and Digital Signature for 'data'
# def block_create_view(request):
#     if request.method == 'POST':
#         first_name = request.POST.get('first')
#         last_name = request.POST.get('last')
#         data = request.POST.get('data')

#         # Encrypt the data before saving
#         encrypted_first_name = cipher.encrypt(first_name.encode()).decode()  # .decode() to store as string
#         encrypted_last_name = cipher.encrypt(last_name.encode()).decode()
#         encrypted_data = cipher.encrypt(data.encode()).decode()

#         # Save encrypted data to the database
#         EncryptedBlock.objects.create(
#             first_name=encrypted_first_name,
#             last_name=encrypted_last_name,
#             data=encrypted_data
#         )

#         messages.success(request, "Data has been encrypted and saved successfully.")

#     # Fetch all encrypted blocks and decrypt them to display on the page
#     encrypted_blocks = EncryptedBlock.objects.all()
#     decrypted_blocks = []

#     for block in encrypted_blocks:
#         try:
#             # Decrypt the data safely
#             decrypted_first_name = cipher.decrypt(block.first_name.encode()).decode()
#             decrypted_last_name = cipher.decrypt(block.last_name.encode()).decode()
#             decrypted_data = cipher.decrypt(block.data.encode()).decode()

#             # Generate hash and digital signature ONLY for the decrypted data field
#             block_hash = generate_hash(decrypted_data)
#             digital_signature = generate_signature(decrypted_data)

#             # Add decrypted data along with hash and digital signature for the data field
#             decrypted_blocks.append({
#                 'first_name': decrypted_first_name,
#                 'last_name': decrypted_last_name,
#                 'data': decrypted_data,
#                 'hash': block_hash,
#                 'signature': digital_signature  # Ensure signature is passed
#             })

#         except Exception as e:
#             print(f"Error decrypting block ID {block.id}: {e}")
#             messages.error(request, f"Error decrypting block ID {block.id}")

#     return render(request, 'block_create.html', {'decrypted_blocks': decrypted_blocks})



# # Other views remain unchanged




# # Block List View (optional if you need to display decrypted data separately)
# def block_list_view(request):
#     encrypted_blocks = EncryptedBlock.objects.all()  # Fetch all encrypted blocks
#     decrypted_blocks = []

#     for block in encrypted_blocks:
#         try:
#             decrypted_first_name = cipher.decrypt(block.first_name.encode()).decode()
#             decrypted_last_name = cipher.decrypt(block.last_name.encode()).decode()
#             decrypted_data = cipher.decrypt(block.data.encode()).decode()

#             # Generate hash for the 'data' field
#             block_hash = generate_hash(decrypted_data)

#             decrypted_blocks.append({
#                 'first_name': decrypted_first_name,
#                 'last_name': decrypted_last_name,
#                 'data': decrypted_data,
#                 'hash': block_hash
#             })
#         except Exception as e:
#             print(f"Error decrypting block ID {block.id}: {e}")
#             messages.error(request, f"Error decrypting block ID {block.id}")

#     return render(request, 'block_list.html', {'blocks': decrypted_blocks})


# # Signup view
# def signup_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         User.objects.create_user(username=username, password=password)
#         messages.success(request, "Account created successfully!")
#         return redirect('login')
    
#     return render(request, 'signup.html')


# # Registration view
# def register_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         firstname = request.POST['firstname']
#         lastname = request.POST['lastname']
#         email = request.POST['email']
#         password = request.POST['password']

#         if not (username and firstname and lastname and email and password):
#             messages.error(request, "All fields are required.")
#             return render(request, 'registration.html')

#         try:
#             user = User.objects.create_user(
#                 username=username,
#                 first_name=firstname,
#                 last_name=lastname,
#                 email=email,
#                 password=password
#             )
#             messages.success(request, "Account created successfully. Please log in.")
#             return redirect('login')

#         except Exception as e:
#             messages.error(request, "Failed to create account: " + str(e))
#             return render(request, 'registration.html')

#     return render(request, 'registration.html')

# # Forgot password view
# def forgot_password_view(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')

#         if not email:
#             messages.error(request, "Please provide a valid email.")
#             return render(request, 'forgot_password.html')

#         # Use filter() instead of get() to handle multiple users with the same email
#         users = User.objects.filter(email=email)

#         if users.exists():
#             for user in users:
#                 otp = random.randint(100000, 999999)  # Generate a random 6-digit OTP

#                 # Save the OTP to the database for each user
#                 OTP.objects.create(user=user, code=otp)

#                 # Send OTP to each user's email
#                 send_mail(
#                     'Your OTP Code',
#                     f'Your OTP code is {otp}',
#                     'noreply@yourdomain.com',
#                     [user.email],
#                     fail_silently=False,
#                 )

#             messages.success(request, 'OTP sent to your email(s).')
#             return redirect('verify_otp')
#         else:
#             messages.error(request, "No account associated with this email.")
#             return render(request, 'forgot_password.html')

#     return render(request, 'forgot_password.html')


# # OTP verification view
# def verify_otp_view(request):
#     if request.method == 'POST':
#         otp = request.POST.get('otp')

#         try:
#             otp_instance = OTP.objects.get(code=otp)
#             messages.success(request, "OTP verified successfully.")
#             request.session['otp_user_id'] = otp_instance.user.id
#             return redirect('reset_password')

#         except OTP.DoesNotExist:
#             messages.error(request, "Invalid OTP. Please try again.")
#             return render(request, 'verify_otp.html')

#     return render(request, 'verify_otp.html')


# # Reset password view
# def reset_password_view(request):
#     if request.method == 'POST':
#         new_password = request.POST.get('new_password')
#         confirm_password = request.POST.get('confirm_password')

#         if new_password != confirm_password:
#             messages.error(request, "Passwords do not match.")
#             return render(request, 'reset_password.html')

#         user_id = request.session.get('otp_user_id')
#         if user_id:
#             try:
#                 user = User.objects.get(id=user_id)
#                 user.set_password(new_password)
#                 user.save()

#                 messages.success(request, "Password reset successfully.")
#                 return redirect('login')

#             except User.DoesNotExist:
#                 messages.error(request, "User not found.")
#                 return render(request, 'reset_password.html')
#         else:
#             messages.error(request, "Session expired. Please request a new OTP.")
#             return redirect('forgot_password')

#     return render(request, 'reset_password.html')


# # Logout view
# def logout_view(request):
#     logout(request)
#     return redirect('login')






# import os
# import hashlib
# from django.shortcuts import render, redirect
# from django.core.mail import send_mail
# from django.contrib.auth import logout, authenticate, login
# from django.contrib.auth.models import User
# from django.contrib import messages
# import random
# from cryptography.fernet import Fernet
# from .models import OTP, EncryptedBlock, Block  # Import the EncryptedBlock and Block models
# from django.conf import settings
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, NoEncryption
# from .blockchain import Blockchain  # Blockchain functionality

# # Get the encryption key from settings or environment variable
# cipher = Fernet(settings.FERNET_KEY.encode())

# # Generate RSA private and public key pair
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# public_key = private_key.public_key()

# # Hash generation function (for the 'data' field)
# def generate_hash(data):
#     return hashlib.sha256(data.encode()).hexdigest()

# # Digital signature generation function (for the 'data' field)
# def generate_signature(data):
#     try:
#         # Use the private key to sign the data
#         signature = private_key.sign(
#             data.encode(),
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),
#                 salt_length=padding.PSS.MAX_LENGTH
#             ),
#             hashes.SHA256()
#         )
#         return signature.hex()  # Convert to hex for easy display
#     except Exception as e:
#         print(f"Error generating signature: {e}")
#         return None

# # Login view
# def login_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             login(request, user)
#             return redirect('block_create')
#         else:
#             messages.error(request, "Invalid username or password.")
#     return render(request, 'login1.html')

# # Block Create View with Encryption, Hashing, Digital Signature, and Blockchain
# def block_create_view(request):
#     blockchain = Blockchain()  # Initialize blockchain (Genesis block is created if needed)

#     if request.method == 'POST':
#         first_name = request.POST.get('first')
#         last_name = request.POST.get('last')
#         data = request.POST.get('data')

#         # Encrypt the data before saving
#         encrypted_first_name = cipher.encrypt(first_name.encode()).decode()  # .decode() to store as string
#         encrypted_last_name = cipher.encrypt(last_name.encode()).decode()
#         encrypted_data = cipher.encrypt(data.encode()).decode()

#         # Create a new block in the blockchain
#         blockchain.create_block(encrypted_data)  # Blockchain handling
        
#         # Save encrypted data to the database
#         EncryptedBlock.objects.create(
#             first_name=encrypted_first_name,
#             last_name=encrypted_last_name,
#             data=encrypted_data
#         )

#         messages.success(request, "Data has been encrypted and added to the blockchain.")

#     # Fetch the blockchain (all blocks)
#     blockchain_data = Block.objects.all().order_by('index')  # Ensure blocks are sorted by index

#     # Fetch and decrypt the blocks
#     encrypted_blocks = EncryptedBlock.objects.all()
#     decrypted_blocks = []

#     for block in encrypted_blocks:
#         try:
#             # Decrypt the data safely
#             decrypted_first_name = cipher.decrypt(block.first_name.encode()).decode()
#             decrypted_last_name = cipher.decrypt(block.last_name.encode()).decode()
#             decrypted_data = cipher.decrypt(block.data.encode()).decode()

#             # Generate hash and digital signature for the decrypted data
#             block_hash = generate_hash(decrypted_data)
#             digital_signature = generate_signature(decrypted_data)

#             # Add decrypted block information to list
#             decrypted_blocks.append({
#                 'first_name': decrypted_first_name,
#                 'last_name': decrypted_last_name,
#                 'data': decrypted_data,
#                 'hash': block_hash,
#                 'signature': digital_signature
#             })

#         except Exception as e:
#             print(f"Error decrypting block ID {block.id}: {e}")
#             messages.error(request, f"Error decrypting block ID {block.id}")

#     return render(request, 'block_create.html', {
#         'decrypted_blocks': decrypted_blocks,
#         'blockchain': blockchain_data,
#     })

# # Block List View to display encrypted data
# def block_list_view(request):
#     encrypted_blocks = EncryptedBlock.objects.all()  # Fetch all encrypted blocks
#     decrypted_blocks = []

#     for block in encrypted_blocks:
#         try:
#             decrypted_first_name = cipher.decrypt(block.first_name.encode()).decode()
#             decrypted_last_name = cipher.decrypt(block.last_name.encode()).decode()
#             decrypted_data = cipher.decrypt(block.data.encode()).decode()

#             # Generate hash and digital signature for the data field
#             block_hash = generate_hash(decrypted_data)
#             digital_signature = generate_signature(decrypted_data)

#             decrypted_blocks.append({
#                 'first_name': decrypted_first_name,
#                 'last_name': decrypted_last_name,
#                 'data': decrypted_data,
#                 'hash': block_hash,
#                 'signature': digital_signature
#             })

#         except Exception as e:
#             print(f"Error decrypting block ID {block.id}: {e}")
#             messages.error(request, f"Error decrypting block ID {block.id}")

#     return render(request, 'block_list.html', {'blocks': decrypted_blocks})

# # Other views remain unchanged

# # Signup view
# def signup_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         User.objects.create_user(username=username, password=password)
#         messages.success(request, "Account created successfully!")
#         return redirect('login')
    
#     return render(request, 'signup.html')

# # Registration view
# def register_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         firstname = request.POST['firstname']
#         lastname = request.POST['lastname']
#         email = request.POST['email']
#         password = request.POST['password']

#         if not (username and firstname and lastname and email and password):
#             messages.error(request, "All fields are required.")
#             return render(request, 'registration.html')

#         try:
#             user = User.objects.create_user(
#                 username=username,
#                 first_name=firstname,
#                 last_name=lastname,
#                 email=email,
#                 password=password
#             )
#             messages.success(request, "Account created successfully. Please log in.")
#             return redirect('login')

#         except Exception as e:
#             messages.error(request, "Failed to create account: " + str(e))
#             return render(request, 'registration.html')

#     return render(request, 'registration.html')

# # Forgot password view
# def forgot_password_view(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')

#         if not email:
#             messages.error(request, "Please provide a valid email.")
#             return render(request, 'forgot_password.html')

#         # Use filter() instead of get() to handle multiple users with the same email
#         users = User.objects.filter(email=email)

#         if users.exists():
#             for user in users:
#                 otp = random.randint(100000, 999999)  # Generate a random 6-digit OTP

#                 # Save the OTP to the database for each user
#                 OTP.objects.create(user=user, code=otp)

#                 # Send OTP to each user's email
#                 send_mail(
#                     'Your OTP Code',
#                     f'Your OTP code is {otp}',
#                     'noreply@yourdomain.com',
#                     [user.email],
#                     fail_silently=False,
#                 )

#             messages.success(request, 'OTP sent to your email(s).')
#             return redirect('verify_otp')
#         else:
#             messages.error(request, "No account associated with this email.")
#             return render(request, 'forgot_password.html')

#     return render(request, 'forgot_password.html')

# # OTP verification view
# def verify_otp_view(request):
#     if request.method == 'POST':
#         otp = request.POST.get('otp')

#         try:
#             otp_instance = OTP.objects.get(code=otp)
#             messages.success(request, "OTP verified successfully.")
#             request.session['otp_user_id'] = otp_instance.user.id
#             return redirect('reset_password')

#         except OTP.DoesNotExist:
#             messages.error(request, "Invalid OTP. Please try again.")
#             return render(request, 'verify_otp.html')

#     return render(request, 'verify_otp.html')

# # Reset password view
# def reset_password_view(request):
#     if request.method == 'POST':
#         new_password = request.POST.get('new_password')
#         confirm_password = request.POST.get('confirm_password')

#         if new_password != confirm_password:
#             messages.error(request, "Passwords do not match.")
#             return render(request, 'reset_password.html')

#         user_id = request.session.get('otp_user_id')
#         if user_id:
#             try:
#                 user = User.objects.get(id=user_id)
#                 user.set_password(new_password)
#                 user.save()

#                 messages.success(request, "Password reset successfully.")
#                 return redirect('login')

#             except User.DoesNotExist:
#                 messages.error(request, "User not found.")
#                 return render(request, 'reset_password.html')
#         else:
#             messages.error(request, "Session expired. Please request a new OTP.")
#             return redirect('forgot_password')

#     return render(request, 'reset_password.html')

# # Logout view
# def logout_view(request):
#     logout(request)
#     return redirect('login')



# import os
# import hashlib
# from django.shortcuts import render, redirect
# from django.core.mail import send_mail
# from django.contrib.auth import logout, authenticate, login
# from django.contrib.auth.models import User
# from django.contrib import messages
# import random
# from cryptography.fernet import Fernet
# from .models import OTP, EncryptedBlock, Block  # Import the EncryptedBlock and Block models
# from django.conf import settings
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, NoEncryption
# from .blockchain import Blockchain  # Blockchain functionality
# import json

# # Get the encryption key from settings or environment variable
# cipher = Fernet(settings.FERNET_KEY.encode())

# # Generate RSA private and public key pair
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# public_key = private_key.public_key()

# # Hash generation function (for the 'data' field)
# def generate_hash(data):
#     return hashlib.sha256(data.encode()).hexdigest()

# # Digital signature generation function (for the 'data' field)
# def generate_signature(data):
#     try:
#         # Use the private key to sign the data
#         signature = private_key.sign(
#             data.encode(),
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),
#                 salt_length=padding.PSS.MAX_LENGTH
#             ),
#             hashes.SHA256()
#         )
#         return signature.hex()  # Convert to hex for easy display
#     except Exception as e:
#         print(f"Error generating signature: {e}")
#         return None

# # Simulated Hyperledger Client SDK communication
# class HyperledgerClient:
#     def __init__(self):
#         self.network_name = "Hyperledger Fabric Test Network"
#         self.chaincode_name = "mychaincode"

#     def query_chaincode(self, function, args):
#         # Simulate querying the chaincode
#         return {
#             "function": function,
#             "args": args,
#             "result": f"Simulated result from Hyperledger Fabric chaincode {self.chaincode_name}"
#         }

#     def invoke_chaincode(self, function, args):
#         # Simulate invoking a chaincode
#         return {
#             "function": function,
#             "args": args,
#             "result": f"Simulated invoke on chaincode {self.chaincode_name} completed"
#         }

# # Login view
# def login_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             login(request, user)
#             return redirect('block_create')
#         else:
#             messages.error(request, "Invalid username or password.")
#     return render(request, 'login1.html')

# # Block Create View with Encryption, Hashing, Digital Signature, and Blockchain
# def block_create_view(request):
#     blockchain = Blockchain()  # Initialize blockchain (Genesis block is created if needed)

#     if request.method == 'POST':
#         first_name = request.POST.get('first')
#         last_name = request.POST.get('last')
#         data = request.POST.get('data')

#         # Encrypt the data before saving
#         encrypted_first_name = cipher.encrypt(first_name.encode()).decode()  # .decode() to store as string
#         encrypted_last_name = cipher.encrypt(last_name.encode()).decode()
#         encrypted_data = cipher.encrypt(data.encode()).decode()

#         # Create a new block in the blockchain
#         blockchain.create_block(encrypted_data)  # Blockchain handling
        
#         # Save encrypted data to the database
#         EncryptedBlock.objects.create(
#             first_name=encrypted_first_name,
#             last_name=encrypted_last_name,
#             data=encrypted_data
#         )

#         messages.success(request, "Data has been encrypted and added to the blockchain.")

#     # Fetch the blockchain (all blocks)
#     blockchain_data = Block.objects.all().order_by('index')  # Ensure blocks are sorted by index

#     # Fetch and decrypt the blocks
#     encrypted_blocks = EncryptedBlock.objects.all()
#     decrypted_blocks = []

#     for block in encrypted_blocks:
#         try:
#             # Decrypt the data safely
#             decrypted_first_name = cipher.decrypt(block.first_name.encode()).decode()
#             decrypted_last_name = cipher.decrypt(block.last_name.encode()).decode()
#             decrypted_data = cipher.decrypt(block.data.encode()).decode()

#             # Generate hash and digital signature for the decrypted data
#             block_hash = generate_hash(decrypted_data)
#             digital_signature = generate_signature(decrypted_data)

#             # Add decrypted block information to list
#             decrypted_blocks.append({
#                 'first_name': decrypted_first_name,
#                 'last_name': decrypted_last_name,
#                 'data': decrypted_data,
#                 'hash': block_hash,
#                 'signature': digital_signature
#             })

#         except Exception as e:
#             print(f"Error decrypting block ID {block.id}: {e}")
#             messages.error(request, f"Error decrypting block ID {block.id}")

#     return render(request, 'block_create.html', {
#         'decrypted_blocks': decrypted_blocks,
#         'blockchain': blockchain_data,
#     })

# # Block List View to display encrypted data
# def block_list_view(request):
#     encrypted_blocks = EncryptedBlock.objects.all()  # Fetch all encrypted blocks
#     decrypted_blocks = []

#     for block in encrypted_blocks:
#         try:
#             decrypted_first_name = cipher.decrypt(block.first_name.encode()).decode()
#             decrypted_last_name = cipher.decrypt(block.last_name.encode()).decode()
#             decrypted_data = cipher.decrypt(block.data.encode()).decode()

#             # Generate hash and digital signature for the data field
#             block_hash = generate_hash(decrypted_data)
#             digital_signature = generate_signature(decrypted_data)

#             decrypted_blocks.append({
#                 'first_name': decrypted_first_name,
#                 'last_name': decrypted_last_name,
#                 'data': decrypted_data,
#                 'hash': block_hash,
#                 'signature': digital_signature
#             })

#         except Exception as e:
#             print(f"Error decrypting block ID {block.id}: {e}")
#             messages.error(request, f"Error decrypting block ID {block.id}")

#     return render(request, 'block_list.html', {'blocks': decrypted_blocks})

# # View for interacting with the simulated Hyperledger client
# def hyperledger_view(request):
#     client = HyperledgerClient()

#     # Example of querying Hyperledger Fabric chaincode
#     query_response = client.query_chaincode("queryBlock", ["block_123"])
    
#     # Example of invoking Hyperledger Fabric chaincode
#     invoke_response = client.invoke_chaincode("addBlock", ["block_123", "some_data"])

#     return render(request, 'hyperledger.html', {
#         'network': client.network_name,
#         'query_response': json.dumps(query_response, indent=4),
#         'invoke_response': json.dumps(invoke_response, indent=4),
#     })

# # Other views remain unchanged
# def signup_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         User.objects.create_user(username=username, password=password)
#         messages.success(request, "Account created successfully!")
#         return redirect('login')
    
#     return render(request, 'signup.html')

# # Registration view
# def register_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         firstname = request.POST['firstname']
#         lastname = request.POST['lastname']
#         email = request.POST['email']
#         password = request.POST['password']

#         if not (username and firstname and lastname and email and password):
#             messages.error(request, "All fields are required.")
#             return render(request, 'registration.html')

#         try:
#             user = User.objects.create_user(
#                 username=username,
#                 first_name=firstname,
#                 last_name=lastname,
#                 email=email,
#                 password=password
#             )
#             messages.success(request, "Account created successfully. Please log in.")
#             return redirect('login')

#         except Exception as e:
#             messages.error(request, "Failed to create account: " + str(e))
#             return render(request, 'registration.html')

#     return render(request, 'registration.html')

# # Forgot password view
# def forgot_password_view(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')

#         if not email:
#             messages.error(request, "Please provide a valid email.")
#             return render(request, 'forgot_password.html')

#         # Use filter() instead of get() to handle multiple users with the same email
#         users = User.objects.filter(email=email)

#         if users.exists():
#             for user in users:
#                 otp = random.randint(100000, 999999)  # Generate a random 6-digit OTP

#                 # Save the OTP to the database for each user
#                 OTP.objects.create(user=user, code=otp)

#                 # Send OTP to each user's email
#                 send_mail(
#                     'Your OTP Code',
#                     f'Your OTP code is {otp}',
#                     'noreply@yourdomain.com',
#                     [user.email],
#                     fail_silently=False,
#                 )

#             messages.success(request, 'OTP sent to your email(s).')
#             return redirect('verify_otp')
#         else:
#             messages.error(request, "No account associated with this email.")
#             return render(request, 'forgot_password.html')

#     return render(request, 'forgot_password.html')

# # OTP verification view
# def verify_otp_view(request):
#     if request.method == 'POST':
#         otp = request.POST.get('otp')

#         try:
#             otp_instance = OTP.objects.get(code=otp)
#             messages.success(request, "OTP verified successfully.")
#             request.session['otp_user_id'] = otp_instance.user.id
#             return redirect('reset_password')

#         except OTP.DoesNotExist:
#             messages.error(request, "Invalid OTP. Please try again.")
#             return render(request, 'verify_otp.html')

#     return render(request, 'verify_otp.html')

# # Reset password view
# def reset_password_view(request):
#     if request.method == 'POST':
#         new_password = request.POST.get('new_password')
#         confirm_password = request.POST.get('confirm_password')

#         if new_password != confirm_password:
#             messages.error(request, "Passwords do not match.")
#             return render(request, 'reset_password.html')

#         user_id = request.session.get('otp_user_id')
#         if user_id:
#             try:
#                 user = User.objects.get(id=user_id)
#                 user.set_password(new_password)
#                 user.save()

#                 messages.success(request, "Password reset successfully.")
#                 return redirect('login')

#             except User.DoesNotExist:
#                 messages.error(request, "User not found.")
#                 return render(request, 'reset_password.html')
#         else:
#             messages.error(request, "Session expired. Please request a new OTP.")
#             return redirect('forgot_password')

#     return render(request, 'reset_password.html')

# # Logout view
# def logout_view(request):
#     logout(request)
#     return redirect('login')






# import os
# import hashlib
# from django.shortcuts import render, redirect
# from django.core.mail import send_mail
# from django.contrib.auth import logout, authenticate, login
# from django.contrib.auth.models import User
# from django.contrib import messages
# import random
# from cryptography.fernet import Fernet
# from .models import OTP, EncryptedBlock, Block  # Import the EncryptedBlock and Block models
# from django.conf import settings
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, NoEncryption
# from .blockchain import Blockchain  # Blockchain functionality
# import json

# # Get the encryption key from settings or environment variable
# cipher = Fernet(settings.FERNET_KEY.encode())

# # Generate RSA private and public key pair
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# public_key = private_key.public_key()

# # Hash generation function (for the 'data' field)
# def generate_hash(data):
#     return hashlib.sha256(data.encode()).hexdigest()

# # Digital signature generation function (for the 'data' field)
# def generate_signature(data):
#     try:
#         # Use the private key to sign the data
#         signature = private_key.sign(
#             data.encode(),
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),
#                 salt_length=padding.PSS.MAX_LENGTH
#             ),
#             hashes.SHA256()
#         )
#         return signature.hex()  # Convert to hex for easy display
#     except Exception as e:
#         print(f"Error generating signature: {e}")
#         return None

# # Simulated Hyperledger Client SDK communication
# class HyperledgerClient:
#     def __init__(self):
#         self.network_name = "Hyperledger Fabric Test Network"
#         self.chaincode_name = "mychaincode"

#     def query_chaincode(self, function, args):
#         # Simulate querying the chaincode
#         return {
#             "function": function,
#             "args": args,
#             "result": f"Simulated result from Hyperledger Fabric chaincode {self.chaincode_name}"
#         }

#     def invoke_chaincode(self, function, args):
#         # Simulate invoking a chaincode
#         return {
#             "function": function,
#             "args": args,
#             "result": f"Simulated invoke on chaincode {self.chaincode_name} completed"
#         }

# # Login view
# def login_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             login(request, user)
#             return redirect('block_create')
#         else:
#             messages.error(request, "Invalid username or password.")
#     return render(request, 'login1.html')

# # Block Create View with Encryption, Hashing, Digital Signature, and Blockchain
# def block_create_view(request):
#     blockchain = Blockchain()  # Initialize blockchain (Genesis block is created if needed)

#     if request.method == 'POST':
#         first_name = request.POST.get('first')
#         last_name = request.POST.get('last')
#         data = request.POST.get('data')

#         # Encrypt the data before saving
#         encrypted_first_name = cipher.encrypt(first_name.encode()).decode()  # .decode() to store as string
#         encrypted_last_name = cipher.encrypt(last_name.encode()).decode()
#         encrypted_data = cipher.encrypt(data.encode()).decode()

#         # Create a new block in the blockchain
#         blockchain.create_block(encrypted_data)  # Blockchain handling
        
#         # Save encrypted data to the database
#         EncryptedBlock.objects.create(
#             first_name=encrypted_first_name,
#             last_name=encrypted_last_name,
#             data=encrypted_data
#         )

#         messages.success(request, "Data has been encrypted and added to the blockchain.")

#     # Fetch the blockchain (all blocks)
#     blockchain_data = Block.objects.all().order_by('index')  # Ensure blocks are sorted by index

#     # Fetch and decrypt the blocks
#     encrypted_blocks = EncryptedBlock.objects.all()
#     decrypted_blocks = []

#     for block in encrypted_blocks:
#         try:
#             # Decrypt the data safely
#             decrypted_first_name = cipher.decrypt(block.first_name.encode()).decode()
#             decrypted_last_name = cipher.decrypt(block.last_name.encode()).decode()
#             decrypted_data = cipher.decrypt(block.data.encode()).decode()

#             # Generate hash and digital signature for the decrypted data
#             block_hash = generate_hash(decrypted_data)
#             digital_signature = generate_signature(decrypted_data)

#             # Add decrypted block information to list
#             decrypted_blocks.append({
#                 'first_name': decrypted_first_name,
#                 'last_name': decrypted_last_name,
#                 'data': decrypted_data,
#                 'hash': block_hash,
#                 'signature': digital_signature
#             })

#         except Exception as e:
#             print(f"Error decrypting block ID {block.id}: {e}")
#             messages.error(request, f"Error decrypting block ID {block.id}")

#     return render(request, 'block_create.html', {
#         'decrypted_blocks': decrypted_blocks,
#         'blockchain': blockchain_data,
#     })

# # Block List View to display encrypted data
# def block_list_view(request):
#     encrypted_blocks = EncryptedBlock.objects.all()  # Fetch all encrypted blocks
#     decrypted_blocks = []

#     for block in encrypted_blocks:
#         try:
#             decrypted_first_name = cipher.decrypt(block.first_name.encode()).decode()
#             decrypted_last_name = cipher.decrypt(block.last_name.encode()).decode()
#             decrypted_data = cipher.decrypt(block.data.encode()).decode()

#             # Generate hash and digital signature for the data field
#             block_hash = generate_hash(decrypted_data)
#             digital_signature = generate_signature(decrypted_data)

#             decrypted_blocks.append({
#                 'first_name': decrypted_first_name,
#                 'last_name': decrypted_last_name,
#                 'data': decrypted_data,
#                 'hash': block_hash,
#                 'signature': digital_signature
#             })

#         except Exception as e:
#             print(f"Error decrypting block ID {block.id}: {e}")
#             messages.error(request, f"Error decrypting block ID {block.id}")

#     return render(request, 'block_list.html', {'blocks': decrypted_blocks})

# # View for interacting with the simulated Hyperledger client
# def hyperledger_view(request):
#     client = HyperledgerClient()

#     # Example of querying Hyperledger Fabric chaincode
#     query_response = client.query_chaincode("queryBlock", ["block_123"])
    
#     # Example of invoking Hyperledger Fabric chaincode
#     invoke_response = client.invoke_chaincode("addBlock", ["block_123", "some_data"])

#     return render(request, 'hyperledger.html', {
#         'network': client.network_name,
#         'query_response': json.dumps(query_response, indent=4),
#         'invoke_response': json.dumps(invoke_response, indent=4),
#     })

# # Other views remain unchanged
# def signup_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         User.objects.create_user(username=username, password=password)
#         messages.success(request, "Account created successfully!")
#         return redirect('login')
    
#     return render(request, 'signup.html')

# # Registration view
# def register_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         firstname = request.POST['firstname']
#         lastname = request.POST['lastname']
#         email = request.POST['email']
#         password = request.POST['password']

#         if not (username and firstname and lastname and email and password):
#             messages.error(request, "All fields are required.")
#             return render(request, 'registration.html')

#         try:
#             user = User.objects.create_user(
#                 username=username,
#                 first_name=firstname,
#                 last_name=lastname,
#                 email=email,
#                 password=password
#             )
#             messages.success(request, "Account created successfully. Please log in.")
#             return redirect('login')

#         except Exception as e:
#             messages.error(request, "Failed to create account: " + str(e))
#             return render(request, 'registration.html')

#     return render(request, 'registration.html')

# # Forgot password view
# def forgot_password_view(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')

#         if not email:
#             messages.error(request, "Please provide a valid email.")
#             return render(request, 'forgot_password.html')

#         # Use filter() instead of get() to handle multiple users with the same email
#         users = User.objects.filter(email=email)

#         if users.exists():
#             for user in users:
#                 otp = random.randint(100000, 999999)  # Generate a random 6-digit OTP

#                 # Save the OTP to the database for each user
#                 OTP.objects.create(user=user, code=otp)

#                 # Send OTP to each user's email
#                 send_mail(
#                     'Your OTP Code',
#                     f'Your OTP code is {otp}',
#                     'noreply@yourdomain.com',
#                     [user.email],
#                     fail_silently=False,
#                 )

#             messages.success(request, 'OTP sent to your email(s).')
#             return redirect('verify_otp')
#         else:
#             messages.error(request, "No account associated with this email.")
#             return render(request, 'forgot_password.html')

#     return render(request, 'forgot_password.html')

# # OTP verification view
# def verify_otp_view(request):
#     if request.method == 'POST':
#         otp = request.POST.get('otp')

#         try:
#             otp_instance = OTP.objects.get(code=otp)
#             messages.success(request, "OTP verified successfully.")
#             request.session['otp_user_id'] = otp_instance.user.id
#             return redirect('reset_password')

#         except OTP.DoesNotExist:
#             messages.error(request, "Invalid OTP. Please try again.")
#             return render(request, 'verify_otp.html')

#     return render(request, 'verify_otp.html')

# # Reset password view
# def reset_password_view(request):
#     if request.method == 'POST':
#         new_password = request.POST.get('new_password')
#         confirm_password = request.POST.get('confirm_password')

#         if new_password != confirm_password:
#             messages.error(request, "Passwords do not match.")
#             return render(request, 'reset_password.html')

#         user_id = request.session.get('otp_user_id')
#         if user_id:
#             try:
#                 user = User.objects.get(id=user_id)
#                 user.set_password(new_password)
#                 user.save()

#                 messages.success(request, "Password reset successfully.")
#                 return redirect('login')

#             except User.DoesNotExist:
#                 messages.error(request, "User not found.")
#                 return render(request, 'reset_password.html')
#         else:
#             messages.error(request, "Session expired. Please request a new OTP.")
#             return redirect('forgot_password')

#     return render(request, 'reset_password.html')

# # Logout view
# def logout_view(request):
#     logout(request)
#     return redirect('login')







# import os
# import hashlib
# from django.shortcuts import render, redirect
# from django.core.mail import send_mail
# from django.contrib.auth import logout, authenticate, login
# from django.contrib.auth.models import User
# from django.contrib import messages
# import random
# from cryptography.fernet import Fernet
# from .models import OTP, EncryptedBlock, Block  # Import the EncryptedBlock and Block models
# from django.conf import settings
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, NoEncryption
# from .blockchain import Blockchain  # Blockchain functionality
# import json

# # Get the encryption key from settings or environment variable
# cipher = Fernet(settings.FERNET_KEY.encode())

# # Generate RSA private and public key pair
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# public_key = private_key.public_key()

# # Hash generation function (for the 'data' field)
# def generate_hash(data):
#     return hashlib.sha256(data.encode()).hexdigest()

# # Digital signature generation function (for the 'data' field)
# def generate_signature(data):
#     try:
#         # Use the private key to sign the data
#         signature = private_key.sign(
#             data.encode(),
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),
#                 salt_length=padding.PSS.MAX_LENGTH
#             ),
#             hashes.SHA256()
#         )
#         return signature.hex()  # Convert to hex for easy display
#     except Exception as e:
#         print(f"Error generating signature: {e}")
#         return None

# # Simulated Hyperledger Client SDK communication
# class HyperledgerClient:
#     def __init__(self):
#         self.network_name = "Hyperledger Fabric Test Network"
#         self.chaincode_name = "mychaincode"

#     def query_chaincode(self, function, args):
#         # Simulate querying the chaincode
#         return {
#             "function": function,
#             "args": args,
#             "result": f"Simulated result from Hyperledger Fabric chaincode {self.chaincode_name}"
#         }

#     def invoke_chaincode(self, function, args):
#         # Simulate invoking a chaincode
#         return {
#             "function": function,
#             "args": args,
#             "result": f"Simulated invoke on chaincode {self.chaincode_name} completed"
#         }

# # Login view
# def login_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             login(request, user)
#             return redirect('block_create')
#         else:
#             messages.error(request, "Invalid username or password.")
#     return render(request, 'login1.html')

# # Block Create View with Encryption, Hashing, Digital Signature, and Blockchain
# def block_create_view(request):
#     blockchain = Blockchain()  # Initialize blockchain (Genesis block is created if needed)

#     if request.method == 'POST':
#         first_name = request.POST.get('first')
#         last_name = request.POST.get('last')
#         data = request.POST.get('data')

#         # Encrypt the data before saving
#         encrypted_first_name = cipher.encrypt(first_name.encode()).decode()  # .decode() to store as string
#         encrypted_last_name = cipher.encrypt(last_name.encode()).decode()
#         encrypted_data = cipher.encrypt(data.encode()).decode()

#         # Create a new block in the blockchain
#         blockchain.create_block(encrypted_data)  # Blockchain handling
        
#         # Save encrypted data to the database
#         EncryptedBlock.objects.create(
#             first_name=encrypted_first_name,
#             last_name=encrypted_last_name,
#             data=encrypted_data
#         )

#         messages.success(request, "Data has been encrypted and added to the blockchain.")

#     # Fetch the blockchain (all blocks)
#     blockchain_data = Block.objects.all().order_by('index')  # Ensure blocks are sorted by index

#     # Fetch encrypted blocks
#     encrypted_blocks = EncryptedBlock.objects.all()

#     return render(request, 'block_create.html', {
#         'blockchain': blockchain_data,
#     })

# # Block List View to display encrypted data
# def block_list_view(request):
#     encrypted_blocks = EncryptedBlock.objects.all()  # Fetch all encrypted blocks

#     return render(request, 'block_list.html', {'blocks': encrypted_blocks})

# # View for interacting with the simulated Hyperledger client
# def hyperledger_view(request):
#     client = HyperledgerClient()

#     # Example of querying Hyperledger Fabric chaincode
#     query_response = client.query_chaincode("queryBlock", ["block_123"])
    
#     # Example of invoking Hyperledger Fabric chaincode
#     invoke_response = client.invoke_chaincode("addBlock", ["block_123", "some_data"])

#     return render(request, 'hyperledger.html', {
#         'network': client.network_name,
#         'query_response': json.dumps(query_response, indent=4),
#         'invoke_response': json.dumps(invoke_response, indent=4),
#     })

# # Other views remain unchanged
# def signup_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         User.objects.create_user(username=username, password=password)
#         messages.success(request, "Account created successfully!")
#         return redirect('login')
    
#     return render(request, 'signup.html')

# # Registration view
# def register_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         firstname = request.POST['firstname']
#         lastname = request.POST['lastname']
#         email = request.POST['email']
#         password = request.POST['password']

#         if not (username and firstname and lastname and email and password):
#             messages.error(request, "All fields are required.")
#             return render(request, 'registration.html')

#         try:
#             user = User.objects.create_user(
#                 username=username,
#                 first_name=firstname,
#                 last_name=lastname,
#                 email=email,
#                 password=password
#             )
#             messages.success(request, "Account created successfully. Please log in.")
#             return redirect('login')

#         except Exception as e:
#             messages.error(request, "Failed to create account: " + str(e))
#             return render(request, 'registration.html')

#     return render(request, 'registration.html')

# # Forgot password view
# def forgot_password_view(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')

#         if not email:
#             messages.error(request, "Please provide a valid email.")
#             return render(request, 'forgot_password.html')

#         # Use filter() instead of get() to handle multiple users with the same email
#         users = User.objects.filter(email=email)

#         if users.exists():
#             for user in users:
#                 otp = random.randint(100000, 999999)  # Generate a random 6-digit OTP

#                 # Save the OTP to the database for each user
#                 OTP.objects.create(user=user, code=otp)

#                 # Send OTP to each user's email
#                 send_mail(
#                     'Your OTP Code',
#                     f'Your OTP code is {otp}',
#                     'noreply@yourdomain.com',
#                     [user.email],
#                     fail_silently=False,
#                 )

#             messages.success(request, 'OTP sent to your email(s).')
#             return redirect('verify_otp')
#         else:
#             messages.error(request, "No account associated with this email.")
#             return render(request, 'forgot_password.html')

#     return render(request, 'forgot_password.html')

# # OTP verification view
# def verify_otp_view(request):
#     if request.method == 'POST':
#         otp = request.POST.get('otp')

#         try:
#             otp_instance = OTP.objects.get(code=otp)
#             messages.success(request, "OTP verified successfully.")
#             request.session['otp_user_id'] = otp_instance.user.id
#             return redirect('reset_password')

#         except OTP.DoesNotExist:
#             messages.error(request, "Invalid OTP. Please try again.")
#             return render(request, 'verify_otp.html')

#     return render(request, 'verify_otp.html')

# # Reset password view
# def reset_password_view(request):
#     if request.method == 'POST':
#         new_password = request.POST.get('new_password')
#         confirm_password = request.POST.get('confirm_password')

#         if new_password != confirm_password:
#             messages.error(request, "Passwords do not match.")
#             return render(request, 'reset_password.html')

#         user_id = request.session.get('otp_user_id')
#         if user_id:
#             try:
#                 user = User.objects.get(id=user_id)
#                 user.set_password(new_password)
#                 user.save()

#                 messages.success(request, "Password reset successfully.")
#                 return redirect('login')

#             except User.DoesNotExist:
#                 messages.error(request, "User not found.")
#                 return render(request, 'reset_password.html')
#         else:
#             messages.error(request, "Session expired. Please request a new OTP.")
#             return redirect('forgot_password')

#     return render(request, 'reset_password.html')

# # Logout view
# def logout_view(request):
#     logout(request)
#     return redirect('login')








import os
import hashlib
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.models import User
from django.contrib import messages
import random
from cryptography.fernet import Fernet
from .models import OTP, EncryptedBlock, Block  # Import the EncryptedBlock and Block models
from django.conf import settings
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, NoEncryption
from .blockchain import Blockchain  # Blockchain functionality
import json

# Get the encryption key from settings or environment variable
cipher = Fernet(settings.FERNET_KEY.encode())

# Generate RSA private and public key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Hash generation function (for the 'data' field)
def generate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Digital signature generation function (for the 'data' field)
def generate_signature(data):
    try:
        # Use the private key to sign the data
        signature = private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()  # Convert to hex for easy display
    except Exception as e:
        print(f"Error generating signature: {e}")
        return None

# Simulated Hyperledger Client SDK communication
class HyperledgerClient:
    def __init__(self):
        self.network_name = "Hyperledger Fabric Test Network"
        self.chaincode_name = "mychaincode"

    def query_chaincode(self, function, args):
        # Simulate querying the chaincode
        return {
            "function": function,
            "args": args,
            "result": f"Simulated result from Hyperledger Fabric chaincode {self.chaincode_name}"
        }

    def invoke_chaincode(self, function, args):
        # Simulate invoking a chaincode
        return {
            "function": function,
            "args": args,
            "result": f"Simulated invoke on chaincode {self.chaincode_name} completed"
        }

# Login view
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('block_create')
        else:
            messages.error(request, "Invalid username or password.")
    return render(request, 'login1.html')

# Block Create View with Encryption, Hashing, Digital Signature, and Blockchain
def block_create_view(request):
    blockchain = Blockchain()  # Initialize blockchain (Genesis block is created if needed)

    if request.method == 'POST':
        first_name = request.POST.get('first')
        last_name = request.POST.get('last')
        data = request.POST.get('data')

        # Encrypt the data before saving
        encrypted_first_name = cipher.encrypt(first_name.encode()).decode()  # .decode() to store as string
        encrypted_last_name = cipher.encrypt(last_name.encode()).decode()
        encrypted_data = cipher.encrypt(data.encode()).decode()

        # Create a new block in the blockchain
        blockchain.create_block(encrypted_data)  # Blockchain handling
        
        # Save encrypted data to the database
        EncryptedBlock.objects.create(
            first_name=encrypted_first_name,
            last_name=encrypted_last_name,
            data=encrypted_data
        )

        messages.success(request, "Data has been encrypted and added to the blockchain.")

    # Fetch the blockchain (all blocks)
    blockchain_data = Block.objects.all().order_by('index')  # Ensure blocks are sorted by index

    return render(request, 'block_create.html', {
        'blockchain': blockchain_data,
    })

# Block List View to display encrypted data
def block_list_view(request):
    encrypted_blocks = EncryptedBlock.objects.all()  # Fetch all encrypted blocks

    return render(request, 'block_list.html', {'blocks': encrypted_blocks})

# View to display decrypted blocks on a dedicated page
def decrypted_blocks_view(request):
    encrypted_blocks = EncryptedBlock.objects.all()  # Fetch all encrypted blocks
    decrypted_blocks = []

    for block in encrypted_blocks:
        try:
            decrypted_first_name = cipher.decrypt(block.first_name.encode()).decode()
            decrypted_last_name = cipher.decrypt(block.last_name.encode()).decode()
            decrypted_data = cipher.decrypt(block.data.encode()).decode()

            # Generate hash and digital signature for the decrypted data
            block_hash = generate_hash(decrypted_data)
            digital_signature = generate_signature(decrypted_data)

            decrypted_blocks.append({
                'first_name': decrypted_first_name,
                'last_name': decrypted_last_name,
                'data': decrypted_data,
                'hash': block_hash,
                'signature': digital_signature
            })
        except Exception as e:
            print(f"Error decrypting block ID {block.id}: {e}")
            messages.error(request, f"Error decrypting block ID {block.id}")

    return render(request, 'decrypted_blocks.html', {'decrypted_blocks': decrypted_blocks})

# View for interacting with the simulated Hyperledger client
def hyperledger_view(request):
    client = HyperledgerClient()

    # Example of querying Hyperledger Fabric chaincode
    query_response = client.query_chaincode("queryBlock", ["block_123"])
    
    # Example of invoking Hyperledger Fabric chaincode
    invoke_response = client.invoke_chaincode("addBlock", ["block_123", "some_data"])

    return render(request, 'hyperledger.html', {
        'network': client.network_name,
        'query_response': json.dumps(query_response, indent=4),
        'invoke_response': json.dumps(invoke_response, indent=4),
    })

# Other views remain unchanged
def signup_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        User.objects.create_user(username=username, password=password)
        messages.success(request, "Account created successfully!")
        return redirect('login')
    
    return render(request, 'signup.html')

# Registration view
def register_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        email = request.POST['email']
        password = request.POST['password']

        if not (username and firstname and lastname and email and password):
            messages.error(request, "All fields are required.")
            return render(request, 'registration.html')

        try:
            user = User.objects.create_user(
                username=username,
                first_name=firstname,
                last_name=lastname,
                email=email,
                password=password
            )
            messages.success(request, "Account created successfully. Please log in.")
            return redirect('login')

        except Exception as e:
            messages.error(request, "Failed to create account: " + str(e))
            return render(request, 'registration.html')

    return render(request, 'registration.html')

# Forgot password view
def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        if not email:
            messages.error(request, "Please provide a valid email.")
            return render(request, 'forgot_password.html')

        # Use filter() instead of get() to handle multiple users with the same email
        users = User.objects.filter(email=email)

        if users.exists():
            for user in users:
                otp = random.randint(100000, 999999)  # Generate a random 6-digit OTP

                # Save the OTP to the database for each user
                OTP.objects.create(user=user, code=otp)

                # Send OTP to each user's email
                send_mail(
                    'Your OTP Code',
                    f'Your OTP code is {otp}',
                    'noreply@yourdomain.com',
                    [user.email],
                    fail_silently=False,
                )

            messages.success(request, 'OTP sent to your email(s).')
            return redirect('verify_otp')
        else:
            messages.error(request, "No account associated with this email.")
            return render(request, 'forgot_password.html')

    return render(request, 'forgot_password.html')

# OTP verification view
def verify_otp_view(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')

        try:
            otp_instance = OTP.objects.get(code=otp)
            messages.success(request, "OTP verified successfully.")
            request.session['otp_user_id'] = otp_instance.user.id
            return redirect('reset_password')

        except OTP.DoesNotExist:
            messages.error(request, "Invalid OTP. Please try again.")
            return render(request, 'verify_otp.html')

    return render(request, 'verify_otp.html')

# Reset password view
def reset_password_view(request):
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'reset_password.html')

        user_id = request.session.get('otp_user_id')
        if user_id:
            try:
                user = User.objects.get(id=user_id)
                user.set_password(new_password)
                user.save()

                messages.success(request, "Password reset successfully.")
                return redirect('login')

            except User.DoesNotExist:
                messages.error(request, "User not found.")
                return render(request, 'reset_password.html')
        else:
            messages.error(request, "Session expired. Please request a new OTP.")
            return redirect('forgot_password')

    return render(request, 'reset_password.html')

# Logout view
def logout_view(request):
    logout(request)
    return redirect('login')
