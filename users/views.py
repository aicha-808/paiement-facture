import json
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from users.models import CustomUser
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from .serializer import CustomUserSerializer 
from django.core.exceptions import ValidationError
from rest_framework.permissions import BasePermission, IsAdminUser, AllowAny, IsAuthenticated
from .utils import send_sms_with_token 
from django.utils.timezone import now
from rest_framework.views import APIView


User = get_user_model()

# Fonction pour générer un token JWT
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# view pour l'inscription
class IsAdminRole(BasePermission):
    """Permission personnalisée pour vérifier si l'utilisateur a le rôle 'admin'."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAdminRole])  # Utilisation de la permission personnalisée
def register_user(request):
    # Récupérer les données
    name = request.data.get('name')
    phone_number = request.data.get('phone_number')
    role = request.data.get('role')
    password = request.data.get('password')

    # Validation
    missing_fields = [field for field in ['name', 'phone_number', 'role', 'password'] if not request.data.get(field)]
    if missing_fields:
        return Response(
            {"error": f"Les champs suivants sont requis : {', '.join(missing_fields)}"},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        # Définir is_staff en fonction du rôle
        is_staff = role.lower() == 'admin'
        # Création de l'utilisateur
        user = CustomUser.objects.create_user(
            name=name,
            phone_number=phone_number,
            role=role,
            password=password,
            is_staff=is_staff 
        )

        # Génération des tokens
        tokens = get_tokens_for_user(user)

        return Response(
            {
                "message": "Utilisateur créé avec succès.",
                "user": CustomUserSerializer(user).data,
                "tokens": tokens
            },
            status=status.HTTP_201_CREATED
        )

    except ValidationError as e:
        return Response({"error": f"Erreur de validation : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({"error": "Une erreur inattendue s'est produite."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# view pour la connexion
@csrf_exempt
def login(request):
    if request.method == 'POST':
        try:
            # Validation du format JSON
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Requête invalide, JSON mal formé.'}, status=400)

        # Validation des champs obligatoires
        phone_number = data.get('phone_number')
        password = data.get('password')
        if not phone_number or not password:
            return JsonResponse({
                'error': "Les champs 'phone_number' et 'password' sont obligatoires."
            }, status=400)

        # Recherche de l'utilisateur et vérification du mot de passe
        user = CustomUser.objects.filter(phone_number=phone_number).first()
        if user and check_password(password, user.password):
            # Générer un token JWT
            refresh = RefreshToken.for_user(user)
            return JsonResponse({
                'message': 'Connexion réussie',
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'role': user.role,
            }, status=200)

        # Identifiants incorrects
        return JsonResponse({'error': 'Identifiants incorrects.'}, status=400)

    # Requête non-POST
    return JsonResponse({'error': 'Seules les requêtes POST sont acceptées.'}, status=405)

# view pour la deconnexion
@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # L'utilisateur doit être authentifié
def logout_view(request):
    """
    Vue pour déconnecter un utilisateur basé sur JWT.
    Invalide le refresh token pour empêcher toute réauthentification.
    """
    try:
        refresh_token = request.data.get('refresh_token')  # Récupérer le token envoyé par le frontend
        token = RefreshToken(refresh_token)  # Valider et obtenir le token
        token.blacklist()  # Ajouter le token à la liste noire
        return JsonResponse({'message': 'Déconnexion réussie.'}, status=200)
    except Exception as e:
        return JsonResponse({'error': 'Une erreur est survenue lors de la déconnexion.'}, status=400)

# Vue pour la demande de réinitialisation du mot de passe
@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])  # Permet à tous les utilisateurs d'accéder
def request_password_reset(request):
    phone_number = request.data.get('phone_number')
    
    if not phone_number:
        return Response({"error": "Le numéro de téléphone est requis."}, status=status.HTTP_400_BAD_REQUEST)

    # Vérifier si l'utilisateur existe avec ce numéro de téléphone
    user = CustomUser.objects.filter(phone_number=phone_number).first()

    if not user:
        return Response({"error": "Aucun utilisateur trouvé avec ce numéro de téléphone."}, status=status.HTTP_404_NOT_FOUND)

    # Générer un token de réinitialisation
    reset_token = user.generate_reset_token()

    # Envoyer un SMS avec Twilio
    try:
        send_sms_with_token(phone_number, reset_token)
        return Response({"message": "Un SMS avec le token de réinitialisation a été envoyé."}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": f"Une erreur est survenue lors de l'envoi du SMS : {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# view pour renitialiser le mot de passe
@csrf_exempt
@api_view(['POST'])
def reset_password(request):
    reset_token = request.data.get('reset_token')
    new_password = request.data.get('new_password')
    
    if not reset_token or not new_password:
        return Response({'error': 'Token et nouveau mot de passe requis.'}, status=status.HTTP_400_BAD_REQUEST)
    
    user = CustomUser.objects.filter(reset_token=reset_token).first()
    
    if not user:
        return Response({'error': 'Token invalide.'}, status=status.HTTP_404_NOT_FOUND)
    
    # Vérifier si le token a expiré
    if user.token_expiration < now():
        return Response({'error': 'Token expiré.'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Mettre à jour le mot de passe
    user.set_password(new_password)
    user.reset_token = None  # Réinitialiser le token
    user.token_expiration = None
    user.save()
    
    return Response({'message': 'Mot de passe réinitialisé avec succès.'}, status=status.HTTP_200_OK)

# View de suppression d'un utilisateur par l'admin
@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_user(request, id):
    """
    Supprime un utilisateur en fonction de son ID.
    """
         # Rechercher l'utilisateur par ID ou phone_number
    user = CustomUser.objects.filter(id=id).first() or \
           CustomUser.objects.filter(phone_number=id).first()
    try:
        # user = CustomUser.objects.get(id=user_id)
        user.delete()
        return Response({"message": "Utilisateur supprimé avec succès."}, status=status.HTTP_200_OK)
    except CustomUser.DoesNotExist:
        return Response({"error": "Utilisateur introuvable."}, status=status.HTTP_404_NOT_FOUND)

# View pour la modification d'un user par l'admin
@api_view(['PUT', 'PATCH'])
@permission_classes([IsAdminUser])
@permission_classes([IsAuthenticated, IsAdminUser])  # Seuls les admins peuvent modifier
def update_user(request, id):
    """
    Met à jour les informations d'un utilisateur en fonction de son ID ou numéro de téléphone.
    """
    # Rechercher l'utilisateur par ID ou phone_number
    user = CustomUser.objects.filter(id=id).first() or \
           CustomUser.objects.filter(phone_number=id).first()

    if not user:
        return Response({"error": "Utilisateur introuvable."}, status=status.HTTP_404_NOT_FOUND)

    # Sérialiser les données et valider
    serializer = CustomUserSerializer(user, data=request.data, partial=True)  # `partial=True` permet une mise à jour partielle
    if serializer.is_valid():
        if request.data.get('password'):  # Gérer le cas particulier du mot de passe
            user.set_password(request.data['password'])
            user.save()
        serializer.save()
        return Response({
            "message": "Utilisateur mis à jour avec succès.",
            "user": serializer.data
        }, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CustomUserListView(APIView):
    def get(self, request):
        # Récupérer tous les utilisateurs CustomUser
        users = CustomUser.objects.all()
        # Sérialiser les utilisateurs avec le CustomUserSerializer
        serializer = CustomUserSerializer(users, many=True)
        return Response(serializer.data)
