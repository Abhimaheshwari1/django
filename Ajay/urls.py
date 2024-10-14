# # Ajay/urls.py

# from django.contrib import admin
# from django.urls import path, include

# urlpatterns = [
#  #  path('admin/', admin.site.urls),
#     path('', include('my_app.urls')),  # Include URLs from your app
# ]


# Ajay/urls.py

# from django.contrib import admin
# from django.urls import path, include

# urlpatterns = [
#     path('admin/', admin.site.urls),
#     path('', include('my_app.urls')),  # Include URLs from your app
# ]

#Ajay/urls.py

# from django.contrib import admin
# from django.urls import path, include

# urlpatterns = [
#     # path('admin/', admin.site.urls),  # Optional, can be commented out if you don't need admin
#     path('', include('my_app.urls')),  # Include the URLs from my_app
# ]



# # my_app/urls.py

# from django.urls import path
# from . import views

# urlpatterns = [
#     path('', views.login_view, name='login'),  # For login1.html
#     path('login/', views.login_view, name='login'),
#     path('block-create/', views.block_create_view, name='block_create'),
#     path('signup/', views.signup_view, name='signup'),
#     path('register/', views.registration_view, name='register'),
#     path('registration/', views.registration_view, name='registration'),  # Add this for /registration/
# ]
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    # Uncomment this line if you want the Django admin panel to work:
    # path('admin/', admin.site.urls),
    
    # Include the URLs from your app
    path('', include('my_app.urls')),  # Include URLs from my_app
]
