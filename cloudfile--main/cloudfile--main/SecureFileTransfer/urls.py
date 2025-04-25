from django.urls import path
from . import views

urlpatterns = [
    path('',views.home,name=''),
     path('signup/', views.signup, name='signup'),
    path('login/', views.login, name='login'),
    path('getapproval/', views.getapproval, name='getapproval'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('home_page/',views.index_page,name='home_page'),
    path('upload/', views.upload_file, name='upload'),
    path('upload/', views.upload_file, name='upload_file'),
     path('decrypt_and_download/', views.decrypt_and_download, name='decrypt_and_download'),
    path('encrypt/', views.encrypt_file, name='encrypt_file'),
    path('senddata/', views.send_userdata, name='senddata'),
    path("upload_s3",views.upload_s3,name="upload_s3"),
     path('approve_upload/', views.approve_upload, name='approve_upload'),
    path('deny_upload/', views.deny_upload, name='deny_upload'),
    path('list_file/',views.download,name='list_file'),
    path('get_password/',views.get_password,name='get_password')
]
