from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
import re
import uuid
from datetime import timedelta
from django.utils.timezone import now

# Gestionnaire personnalisé pour l'utilisateur
class UserManager(BaseUserManager):
    def create_user(self, name, phone_number, password=None, **extra_fields):
        """Crée et renvoie un utilisateur avec un numéro de téléphone et un mot de passe."""
        if not phone_number:
            raise ValueError("Le numéro de téléphone doit être défini")
        if not self.validate_password(password):  # Validation du mot de passe
            raise ValidationError(
                "Le mot de passe doit contenir : Au moins une majuscule,Au moins une minuscule,Au moins un chiffre,Au moins un caractère spécial,Longueur minimale de 8 caractères. "
            )
        # Définir le rôle par défaut si non fourni
        role = extra_fields.pop('role', 'membre')
        if role not in dict(self.model.ROLE_CHOICES):
            raise ValueError("Le rôle doit être 'admin' ou 'membre'.")

        extra_fields.setdefault('is_active', True)
        user = self.model(name=name, phone_number=phone_number, role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, name, phone_number, password=None, **extra_fields):
        """Crée et renvoie un superutilisateur."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')  # Définir le rôle comme admin

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Le superutilisateur doit avoir is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Le superutilisateur doit avoir is_superuser=True.")

        return self.create_user(name, phone_number, password, **extra_fields)

    @staticmethod
    def validate_password(password):
        """Valide le mot de passe selon les critères définis."""
        if not password:
            return False
        regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\'":\\|,.<>\/?]).{8,}$'
        return bool(re.match(regex, password))


# Modèle utilisateur personnalisé
class CustomUser(AbstractBaseUser, PermissionsMixin):
    # Définition des rôles
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('membre', 'Membre'),
    )

    # Expression régulière pour le numéro de téléphone
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Le numéro de téléphone doit être au format international : '+123456789' avec 9 à 15 chiffres."
    )

    name = models.CharField(max_length=50, unique=True)
    phone_number = models.CharField(validators=[phone_regex], max_length=17, unique=True)  # Numéro de téléphone unique
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    reset_token = models.CharField(max_length=100, blank=True, null=True)  # Token de réinitialisation
    token_expiration = models.DateTimeField(blank=True, null=True) 

    objects = UserManager()
    
    def generate_reset_token(self):
        """Génère un token de réinitialisation et le définit pour l'utilisateur."""
        self.reset_token = str(uuid.uuid4())  # Crée un token unique
        self.token_expiration = now() + timedelta(hours=1)  # Définit une expiration dans 1 heure
        self.save()
        return self.reset_token
    
    # Définir le champ 'USERNAME_FIELD' pour qu'il soit le numéro de téléphone
    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['name', 'role']

    def __str__(self):
        return self.name
