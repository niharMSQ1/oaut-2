from django.shortcuts import render

# Create your views here.
from django.contrib.auth.models import User, Group
from django.contrib.auth.hashers import make_password
from django.shortcuts import render
from django.http import JsonResponse

# Create your views here.
from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope, TokenHasScope
from rest_framework import generics, permissions
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework import status


from .serializer import UserSerializer, GroupSerializer
from .dbUtils import get_connection


class UserList(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]
    queryset = User.objects.all()
    serializer_class = UserSerializer

class UserDetails(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]
    queryset = User.objects.all()
    serializer_class = UserSerializer

class GroupList(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated, TokenHasScope]
    required_scopes = ['groups']
    queryset = Group.objects.all()
    serializer_class = GroupSerializer

class UserCreate(APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')

        if not username or not password:
            return JsonResponse({"error": "Username and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return JsonResponse({"error": "Username already exists."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=make_password(password)  # Hash the password
        )

        return JsonResponse({"message": "User created successfully."}, status=status.HTTP_201_CREATED)
    
def test(request):
    connection = get_connection()
    if connection and connection.is_connected():
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM servers")
    else:
        return JsonResponse({"message":"some error o"})

def connect_to_database(request):
    connection = get_connection()
    if connection and connection.is_connected():
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM servers")
            rows = cursor.fetchall()
            return JsonResponse({"data": rows})
        except Exception as e:
            print(f"Error: {e}")
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)

def noOfAssets(request):
    connection = get_connection()
    if connection and connection.is_connected():
        try:
            cursor = connection.cursor(dictionary=True)

            cursor.execute("""
                SELECT organization_id, COUNT(*) AS count
                FROM servers
                GROUP BY organization_id
            """)
            servers_counts = cursor.fetchall()

            cursor.execute("""
                SELECT organization_id, COUNT(*) AS count
                FROM workstations
                GROUP BY organization_id
            """)
            workstations_counts = cursor.fetchall()

            result = {
                "servers_counts": {row['organization_id']: row['count'] for row in servers_counts},
                "workstations_counts": {row['organization_id']: row['count'] for row in workstations_counts}


            }
            combined_counts = {}

            for org_id, server_count in result['servers_counts'].items():
                workstation_count = result['workstations_counts'].get(org_id, 0)
                if workstation_count > 0:
                    combined_counts[org_id] = server_count + workstation_count

            

            return JsonResponse({
                "combined-count":combined_counts,
                "separated-count":result
            })
        
        except Exception as e:
            print(f"Error: {e}")
            return JsonResponse({"error": str(e)}, status=500)
    
    else:
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)
    
def vulnerabilities_per_organization(request):
    connection = get_connection()
    if connection and connection.is_connected():
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
        SELECT 
            cv.organization_id, 
            o.name AS organization_name, 
            COUNT(DISTINCT cv.vulnerabilities_id) AS vulnerabilities_count
        FROM 
            organizations AS o
        JOIN 
            (
                SELECT 
                    w.organization_id, 
                    a.vulnerabilities_id 
                FROM 
                    workstations AS w
                JOIN 
                    assetables AS a 
                ON 
                    w.id = a.assetable_id 
                WHERE 
                    a.assetable_type LIKE '%workstation%'
                UNION
                SELECT 
                    s.organization_id, 
                    a.vulnerabilities_id 
                FROM 
                    servers AS s
            JOIN 
                    assetables AS a 
                ON 
                    s.id = a.assetable_id 
                WHERE 
                    a.assetable_type LIKE '%servers%'
            ) AS cv 
        ON 
            o.id = cv.organization_id
        GROUP BY 
            cv.organization_id;
    """)
        result = cursor.fetchall()
        print(result)
        return JsonResponse({"data":result})
    
def critical_vulnerabilities_count(request):
    connection = get_connection()
    if connection and connection.is_connected():
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
        SELECT 
            cv.organization_id, 
            o.name AS organization_name, 
            COUNT(DISTINCT cv.vulnerabilities_id) AS vulnerabilities_count,
            COUNT(DISTINCT CASE WHEN v.risk > 8 THEN cv.vulnerabilities_id END) AS critical_vulnerabilities_count
        FROM 
            organizations AS o
        JOIN 
            (
                SELECT 
                    w.organization_id, 
                    a.vulnerabilities_id 
                FROM 
                    workstations AS w
                JOIN 
                    assetables AS a 
                ON 
                    w.id = a.assetable_id 
                WHERE 
                    a.assetable_type LIKE '%workstation%'
                UNION
                SELECT 
                    s.organization_id, 
                    a.vulnerabilities_id 
                FROM 
                    servers AS s
                JOIN 
                    assetables AS a 
                ON 
                    s.id = a.assetable_id 
                WHERE 
                    a.assetable_type LIKE '%servers%'
            ) AS cv 
        ON 
            o.id = cv.organization_id
        JOIN 
            vulnerabilities AS v
        ON 
            cv.vulnerabilities_id = v.id
        GROUP BY 
            cv.organization_id, 
            o.name;

    """)
        result = cursor.fetchall()
        print(result)
        return JsonResponse({"data":result})
    
def critical_assets_count(request):
    connection = get_connection()
    if connection and connection.is_connected():
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
        SELECT 
            cv.organization_id, 
            o.name AS organization_name, 
            COUNT(DISTINCT cv.vulnerabilities_id) AS vulnerabilities_count,
            COUNT(DISTINCT CASE WHEN v.risk > 8 THEN cv.vulnerabilities_id END) AS critical_vulnerabilities_count,
            COUNT(DISTINCT CASE WHEN v.risk > 8 THEN cv.asset_id END) AS critical_assets_count
        FROM 
            organizations AS o
        JOIN 
            (
                SELECT 
                    w.organization_id, 
                    a.vulnerabilities_id, 
                    w.id AS asset_id
                FROM 
                    workstations AS w
                JOIN 
                    assetables AS a 
                ON 
                    w.id = a.assetable_id 
                WHERE 
                    a.assetable_type LIKE '%workstation%'
                UNION
                SELECT 
                    s.organization_id, 
                    a.vulnerabilities_id,
                    s.id AS asset_id
                FROM 
                    servers AS s
                JOIN 
                    assetables AS a 
                ON 
                    s.id = a.assetable_id 
                WHERE 
                    a.assetable_type LIKE '%servers%'
            ) AS cv 
        ON 
            o.id = cv.organization_id
        JOIN 
            vulnerabilities AS v
        ON 
            cv.vulnerabilities_id = v.id
        GROUP BY 
            cv.organization_id, 
            o.name;


    """)
        result = cursor.fetchall()
        print(result)
        return JsonResponse({"data":result})
