from django.contrib import admin
from django.urls import path, include

from oauth_test.views import UserList, UserDetails, GroupList
from .views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    path('users/', UserList.as_view()),
    path('users/<pk>/', UserDetails.as_view()),
    path('groups/', GroupList.as_view()),
    path('create_user/', UserCreate.as_view(), name='create_user'),

    
    path('', test),
    path('connect-db',connect_to_database),
    path('no-of-assets',noOfAssets),
    path('vulnerabilities-per-organization',vulnerabilities_per_organization),
    path('critical-vulnerabilities-count',critical_vulnerabilities_count),
    path('critical-assets-count',critical_assets_count),
]