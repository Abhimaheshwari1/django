# # # # my_app/urls.py

# # # from django.urls import path
# # # from . import views  # Import views from your app

# # # urlpatterns = [
# # #     # Define your app's URL patterns here
# # #     path('', views.index, name='index'),  # Example view
# # #     path('', views.index),
# # # ]


# # # # my_app/urls.py

# # # from django.urls import path
# # # from . import views

# # # urlpatterns = [
# # #     path('login/', views.login_view, name='login'),
# # # ]



# # # my_app/urls.py
# # # my_app/urls.py

# # from django.urls import path
# # from . import views

# # urlpatterns = [
# #     path('', views.login_view, name='login'),  # Root URL points to login1.html
# #     path('login/', views.login_view, name='login'),  # URL for login1.html
# #     path('block-create/', views.block_create_view, name='block_create'),  # URL for block_create.html
# #      path('signup/', views.signup_view, name='signup'), 
# #     path('register/', views.registration_view, name='register'),  # URL for registration.html
# # ]

# # # from django.urls import path
# # # from . import views

# # # urlpatterns = [
# # #     path('', views.login_view, name='login'),  # For login1.html
# # #     path('login/', views.login_view, name='login'),
# # #     path('signup/', views.signup_view, name='signup'),  # Add this line for signup
# # # ]



# from django.urls import path
# from . import views

# urlpatterns = [
#     path('', views.login_view, name='login'),  # Root URL points to login1.html
#     path('login/', views.login_view, name='login'),  # URL for login1.html
#     path('block-create/', views.block_create_view, name='block_create'),  # URL for block_create.html
#     path('signup/', views.signup_view, name='signup'),  # URL for signup
#     path('register/', views.register_view, name='register'),  # Correct the view to register_view (was registration_view)
#     path('block-create/', views.block_create_view, name='block_create'),
#     path('block-create/', views.block_create_view, name='block_create'),
#     path('logout/', views.logout_view, name='logout'),  # Add this for the logout functionality
#     # other URL patterns
# ]



# from django.urls import path
# from . import views

# urlpatterns = [
#     path('', views.login_view, name='login'),  # Root URL points to login1.html
#     path('login/', views.login_view, name='login'),  # URL for login1.html
#     path('block-create/', views.block_create_view, name='block_create'),  # URL for block_create.html
#     path('signup/', views.signup_view, name='signup'),  # URL for signup.html
#     path('block-create/', views.block_create_view, name='block_create'),
#      path('forgot-password/', views.forgot_password_view, name='forgot_password'),
#     path('send-otp/', views.send_otp_view, name='send_otp'),
#     path('verify-otp/', views.verify_otp_view, name='verify_otp'),
#     path('register/', views.register_view, name='register'),  # URL for registration.html
#     path('logout/', views.logout_view, name='logout'),  # URL for logout
#     path('reset-password/', views.reset_password_view, name='reset_password'),
# ]
from .views import block_list_view, hyperledger_view, block_create_view, hyperledger_view
from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),  # Root URL points to login1.html
    path('login/', views.login_view, name='login'),  # URL for login1.html
    path('block-create/', views.block_create_view, name='block_create'),  # URL for block_create.html
    path('signup/', views.signup_view, name='signup'),  # URL for signup.html
    path('register/', views.register_view, name='register'),  # URL for registration.html
    path('logout/', views.logout_view, name='logout'),  # URL for logout
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),  # URL for forgot password
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),  # URL for OTP verification
    path('reset-password/', views.reset_password_view, name='reset_password'),  # URL for password reset
    path('block/create/', views.block_create_view, name='block_create'),
    path('block/list/', block_list_view, name='block_list'),
    path('hyperledger/', hyperledger_view, name='hyperledger_interaction'),
     path('block/create/', block_create_view, name='block_create'),
    path('block/list/', block_list_view, name='block_list'),
    path('hyperledger/', hyperledger_view, name='hyperledger_view'),
    path('decrypted/', views.decrypted_blocks_view, name='decrypted_blocks'),

]
