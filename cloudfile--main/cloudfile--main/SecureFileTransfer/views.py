from django.shortcuts import render,redirect
from django.core.files.storage import FileSystemStorage
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import uuid
import os
from django.contrib.auth import authenticate, login
from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from django.http import HttpResponse
import urllib.parse
from django.views.decorators.csrf import csrf_exempt  # optional if needed
import boto3
from django.http import JsonResponse
import json
from django.contrib.auth.models import User
import re,random
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import StoreUserDatas,EncryptedUpload  # Make sure this matches your model file name
def home(request):
    return render(request,"home.html")





@csrf_exempt
def signup(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return JsonResponse({'success': False, 'error': 'All fields are required.'})

        if StoreUserDatas.objects.filter(email=email).exists():
            return JsonResponse({'success': False, 'error': 'Email already exists.'})
        if StoreUserDatas.objects.filter(username=username).exists():
            return JsonResponse({'success': False, 'error': 'Username already exists.'})

        # Save plain password (or hash it if needed)
        StoreUserDatas.objects.create(username=username, email=email, password=password)
        return JsonResponse({'success': True})

    return JsonResponse({'success': False, 'error': 'Invalid request method.'})




@csrf_exempt
def login(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        identifier = data.get('username')  # Can be username or email
        password = data.get('password')

        if not identifier or not password:
            return JsonResponse({'success': False, 'error': 'All fields are required.'})

        user = None

        if StoreUserDatas.objects.filter(username=identifier).exists():
            user = StoreUserDatas.objects.get(username=identifier)
        elif StoreUserDatas.objects.filter(email=identifier).exists():
            user = StoreUserDatas.objects.get(email=identifier)

        if user and user.password == password:  # Plaintext password check
            request.session['user_email'] = user.email
            print(request.session.get('user_email'))
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': 'Invalid credentials.'})

    return JsonResponse({'success': False, 'error': 'Invalid request method.'})

def getapproval(request):
    email = request.session.get('user_email')
    if not email:
        return redirect('/login/')

    otp = str(random.randint(100000, 999999))
    request.session['otp'] = otp

    send_mail(
        subject='Your OTP for Secure File System',
        message=f'Your OTP is {otp}',
        from_email='your_email@example.com',
        recipient_list=[email],
        fail_silently=False,
    )
    return render(request, 'email_approval.html')

@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        input_otp = request.POST.get('otp')
        session_otp = request.session.get('otp')

        if input_otp == session_otp:
            del request.session['otp']
            return redirect('/home_page/')
        else:
            return render(request, 'email_approval.html', {'error': 'Invalid OTP'})

    return redirect('/getapproval/')

def index_page(request):
    return render(request,'login.html')
def upload_file(request):
    file_uploaded = False
    file_url = None
    uploaded_filename = None

    upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
    os.makedirs(upload_dir, exist_ok=True)

    fs = FileSystemStorage(location=upload_dir)

    if request.method == 'POST' and request.FILES.get('uploaded_file'):
        uploaded_file = request.FILES['uploaded_file']
        filename = fs.save(uploaded_file.name, uploaded_file)
        request.session['filename'] = filename
        file_uploaded = True
        uploaded_filename = filename
        file_url = os.path.join(settings.MEDIA_URL, 'uploads', filename)  # Construct public URL

    return render(request, 'upload.html', {
        'file_uploaded': file_uploaded,
        'uploaded_filename': uploaded_filename,
        'file_url': file_url
    })

    return render(request, 'upload.html', {'file_uploaded': file_uploaded})
def encrypt_file(request):
    uploaded_files = []

    # Get the most recently uploaded filename from session
    filename = request.session.get('filename')

    if filename:
        upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
        file_path = os.path.join(upload_dir, filename)

        # Check if the file exists before showing
        if os.path.exists(file_path):
            uploaded_files.append(filename)

    return render(request, "encrypt.html", {"uploaded_files": uploaded_files})



# Function to encrypt the file using AES-256
def aes_encrypt_file(file_path, password, output_dir):
    key = hashlib.sha256(password.encode()).digest()  # Create 256-bit key from password

    with open(file_path, 'rb') as f:
        data = f.read()

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_data = cipher.encrypt(data)
    # Create encrypted file name and path
    encrypted_filename = os.path.basename(file_path) + '.enc'
   

    
    encrypted_path = os.path.join(output_dir, encrypted_filename)
    with open(encrypted_path, 'wb') as f:
        f.write(iv + encrypted_data)  # Save IV + encrypted data

    return encrypted_path,encrypted_filename


def send_userdata(request):
    message = ""
    uploaded_files = []

    if request.method == 'POST':
        filename = request.session.get("filename")
        password = request.POST.get("password")

        if not filename or not password:
            message = "Please provide both a file and password."
        else:
            try:
                # Define source and target paths
                upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
                encrypted_dir = os.path.join(settings.MEDIA_ROOT, 'encrypted_folder')
                os.makedirs(encrypted_dir, exist_ok=True)

                file_path = os.path.join(upload_dir, filename)

                if not os.path.exists(file_path):
                    message = f"File '{filename}' not found."
                else:
                    # Encrypt the file
                    encrypted_path, encrypted_name = aes_encrypt_file(file_path, password, encrypted_dir)
                    encrypted_name = os.path.basename(encrypted_path)
                    request.session['filename_enc'] = encrypted_name
                    request.session['password']=password
                    email=request.session.get('user_email')
                    EncryptedUpload.objects.create(
                        email=email,
                        filename=encrypted_name,
                        password=password  # Note: In production, avoid storing plaintext passwords
                    )

                    message = f"File encrypted successfully: {encrypted_name}"

                    # Show only the recently encrypted file
                    return render(request, "s3.html", {
                        "message": message,
                        "uploaded_files": [encrypted_name]
                    })

            except Exception as e:
                message = f"Encryption failed: {str(e)}"

    # On error or fallback
    upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
    if os.path.exists(upload_dir) and filename:
        uploaded_files = [filename]

    return render(request, "s3.html", {
        "message": message,
        "uploaded_files": uploaded_files
    })



def upload_s3(request):
    message = ""
    uploaded_files = []

    upload_dir = os.path.join(settings.MEDIA_ROOT, 'encrypted_folder')
    if os.path.exists(upload_dir):
        uploaded_files = [f for f in os.listdir(upload_dir) if f.endswith('.enc')]

    if request.method == 'POST':
        filename = request.session.get('filename_enc')
        
        if filename:
            # Encode filename to safely send in URL
            encoded_filename = urllib.parse.quote(filename)

            # Generate approval links
            approve_link = request.build_absolute_uri(reverse('approve_upload') + f'?filename={encoded_filename}')
            deny_link = request.build_absolute_uri(reverse('deny_upload') + f'?filename={encoded_filename}')

            # Send email with approve/deny links
            send_mail(
                subject='Approval Required: Upload File to S3',
                message=f"Click to approve: {approve_link}\nClick to deny: {deny_link}",
                from_email='your_email@example.com',
                recipient_list=['user@example.com'],  # Change to real recipient
            )

            message = f"Approval email sent for file: {filename}"

    return render(request, "s3.html", {
        "uploaded_files": uploaded_files,
        "message": message
    })

def approve_upload(request):
    filename = request.session.get('filename_enc')
    email = request.session.get('user_email')

    if filename and email:
        upload_dir = os.path.join(settings.MEDIA_ROOT, 'encrypted_folder')
        file_path = os.path.join(upload_dir, filename)

        if os.path.exists(file_path):
            # Load AWS credentials and config
            aws_access_key = os.getenv('AWS_ACCESS_KEY')
            aws_secret_key = os.getenv('AWS_SECRET_KEY')
            aws_region = os.getenv('AWS_REGION')
            bucket_name = os.getenv('BUCKET_NAME')

            try:
                s3 = boto3.client(
                    's3',
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=aws_region
                )

                # Use email as folder prefix
                s3_key = f'{email}/encrypted/{filename}'

                with open(file_path, 'rb') as f:
                    s3.upload_fileobj(f, bucket_name, s3_key)

                return render(request,'sucessfull.html')

            except Exception as e:
                return HttpResponse(f"Upload failed: {str(e)}")
        else:
            return HttpResponse("File not found.")

    return HttpResponse("Invalid request.")



def deny_upload(request):
    filename = request.GET.get("filename")
    if filename:
        print(f"{filename} upload denied.")
        return HttpResponse(f"{filename} upload has been denied.")
    return HttpResponse("Invalid request.")



def download(request):
    email = request.session.get('user_email')  # identify the user

    if not email:
        return HttpResponse("Unauthorized: Email not found in session.", status=401)

    aws_access_key = os.getenv('AWS_ACCESS_KEY')
    aws_secret_key = os.getenv('AWS_SECRET_KEY')
    aws_region = os.getenv('AWS_REGION')
    bucket_name = os.getenv('BUCKET_NAME')

    s3 = boto3.client(
        's3',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )

    try:
        # Use user's email as the prefix
        prefix = f"{email}/encrypted/"
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        files = []

        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                if key != prefix:
                    filename_only = key.replace(prefix, '')  # Strip the user's folder
                    files.append(filename_only)

        return render(request, 'download.html', {'files': files, 'email': email})
    
    except Exception as e:
        return render(request, 'download.html', {'error': str(e)})
import boto3
import hashlib
from Crypto.Cipher import AES
from django.http import HttpResponse
import os

def aes_decrypt_file(encrypted_data, password):
    """
    AES-256 Decryption function.
    - encrypted_data: The encrypted file data.
    - password: The password used for decryption.
    """
    # Create 256-bit key from password using SHA-256
    key = hashlib.sha256(password.encode()).digest()

    # Extract the IV (first 16 bytes)
    iv = encrypted_data[:16]
    cipher_text = encrypted_data[16:]

    # Initialize the cipher with the key and IV for decryption
    cipher = AES.new(key, AES.MODE_CFB, iv)

    # Decrypt the data
    decrypted_data = cipher.decrypt(cipher_text)

    return decrypted_data

def decrypt_and_download(request):
    """
    View for decrypting and downloading an encrypted file from S3.
    - file_name: Name of the encrypted file.
    - password: Password for decrypting the file.
    """
    if request.method == 'POST':
        file_name = request.POST.get('file_name')  # Name of the encrypted file
        password = request.POST.get('password')  # Password entered by user
        user_email = request.session.get('user_email')  # Fetch user email from session

        # Initialize the S3 client with AWS credentials
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY'),
            aws_secret_access_key=os.getenv('AWS_SECRET_KEY'),
            region_name=os.getenv('AWS_REGION')
        )

        try:
            # Construct S3 key using user-specific folder structure
            s3_key = s3_key = f'{user_email}/encrypted/{file_name}'

            print(s3_key)
            # Get the encrypted file from S3
            obj = s3.get_object(Bucket=os.getenv('BUCKET_NAME'), Key=s3_key)
            encrypted_data = obj['Body'].read()

            # Decrypt the file using the password provided by the user
            decrypted_data = aes_decrypt_file(encrypted_data, password)

            # Remove the .enc extension from the filename for the decrypted file
            decrypted_file_name = file_name.replace('.enc', '')

            # Return the decrypted file as a response for download
            response = HttpResponse(decrypted_data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{decrypted_file_name}"'

            return response

        except Exception as e:
            # Catch any exceptions (e.g., wrong password, file not found) and return an error message
            return HttpResponse(f"Failed to download or decrypt: {str(e)}", status=500)


@csrf_exempt  # Optional: only if CSRF issues occur during testing
def get_password(request):
    if request.method == "POST":
        filename = request.POST.get("file_name")
        email = request.session.get("user_email")
        print("All database entries:")
        for entry in EncryptedUpload.objects.all():
            print(f"Filename: {entry.filename}, Email: {entry.email}, Password: {entry.password}")
        if not filename or not email:
            return HttpResponse("Invalid request: Missing filename or email.", status=400)

        try:
            # Retrieve the encrypted upload object
            file_entry = EncryptedUpload.objects.get(filename=filename, email=email)

            # Send the password via email
            send_mail(
                subject="Your file password",
                message=f"The password for your file '{filename}' is: {file_entry.password}",
                from_email="your_email@example.com",  # Replace with your sender email
                recipient_list=[email],
                fail_silently=False,
            )

            return HttpResponse(f"Password for '{filename}' has been sent to {email}.")
        
        except EncryptedUpload.DoesNotExist:
            return HttpResponse("File entry not found for this user.", status=404)
        except Exception as e:
            return HttpResponse(f"Error: {str(e)}", status=500)

    return HttpResponse("Method not allowed", status=405)



