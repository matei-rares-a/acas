from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
import secrets
import json
from django.views.decorators.csrf import csrf_exempt
from .models import Commitment, User, AuthToken

# Public parameters from calculations.py
P = 2089
G = 2

# For larger scale, these should be from calculations.py


@csrf_exempt
@require_http_methods(["POST"])
def register(request):
    """Handle user registration with Schnorr protocol"""
    try:
        data = json.loads(request.body)
        client_id = data.get("client_id")
        secret = data.get("secret")  # y = g^x mod p
        
        if not client_id or secret is None:
            return JsonResponse({"status": "failed", "reason": "missing parameters"}, status=400)
        
        # Create or update user
        user, created = User.objects.update_or_create(
            client_id=client_id,
            defaults={"secret_y": str(secret)}
        )
        
        status_msg = "registered" if created else "updated"
        return JsonResponse({"status": status_msg, "client_id": client_id})
    except Exception as e:
        return JsonResponse({"status": "failed", "reason": str(e)}, status=400)


@csrf_exempt
@require_http_methods(["POST"])
def commit(request):
    """Handle commitment phase of Schnorr proof"""
    try:
        data = json.loads(request.body)
        client_id = data.get("client_id")
        t = data.get("t")
        
        if not client_id or t is None:
            return JsonResponse({"status": "failed", "reason": "missing parameters"}, status=400)
        
        # Verify user exists
        try:
            User.objects.get(client_id=client_id)
        except User.DoesNotExist:
            return JsonResponse({"status": "failed", "reason": "user not registered"}, status=400)
        
        # Save or update commitment
        Commitment.objects.update_or_create(
            client_id=client_id,
            defaults={"t": str(t)}
        )
        
        # Generate random challenge
        c = secrets.randbelow(P - 2) + 1
        
        return JsonResponse({"status": "committed", "c": c})
    except Exception as e:
        return JsonResponse({"status": "failed", "reason": str(e)}, status=400)


@csrf_exempt
@require_http_methods(["POST"])
def verify(request):
    """Verify Schnorr proof"""
    try:
        data = json.loads(request.body)
        client_id = data.get("client_id")
        s = data.get("s")
        c = data.get("c")
        
        if not client_id or s is None or c is None:
            return JsonResponse({"status": "failed", "reason": "missing parameters"}, status=400)
        
        # Retrieve user
        try:
            user = User.objects.get(client_id=client_id)
            y = int(user.secret_y)
        except User.DoesNotExist:
            return JsonResponse({"status": "failed", "reason": "user not found"}, status=400)
        
        # Retrieve commitment
        try:
            commitment = Commitment.objects.get(client_id=client_id)
            t = int(commitment.t)
        except Commitment.DoesNotExist:
            return JsonResponse({"status": "failed", "reason": "no commitment"}, status=400)
        
        # Verify Schnorr proof: g^s ≡ t * y^c (mod p)
        left = pow(G, s, P)
        right = (t * pow(y, c, P)) % P
        
        if left == right:
            # Create authentication token
            token, _ = AuthToken.objects.update_or_create(
                user=user,
                defaults={"token": secrets.token_hex(32)}
            )
            
            # Clean up commitment after successful verification
            commitment.delete()
            return JsonResponse({
                "status": "authenticated",
                "token": token.token,
                "client_id": client_id
            })
        else:
            return JsonResponse({"status": "failed", "reason": "verification failed"})
    except Exception as e:
        return JsonResponse({"status": "failed", "reason": str(e)}, status=400)


@csrf_exempt
@require_http_methods(["POST"])
def forgetme(request):
    """Delete user data - GDPR right to be forgotten"""
    try:
        data = json.loads(request.body)
        client_id = data.get("client_id")
        token = data.get("token")
        
        if not client_id:
            return JsonResponse({"status": "failed", "reason": "missing client_id"}, status=400)
        
        try:
            user = User.objects.get(client_id=client_id)
            
            # Verify token if provided
            if token:
                try:
                    auth_token = AuthToken.objects.get(user=user, token=token)
                except AuthToken.DoesNotExist:
                    return JsonResponse({"status": "failed", "reason": "invalid token"}, status=400)
            
            # Delete user and related data
            user.delete()
            return JsonResponse({"status": "forgotten", "message": "User data deleted"})
        except User.DoesNotExist:
            return JsonResponse({"status": "failed", "reason": "user not found"}, status=400)
    except Exception as e:
        return JsonResponse({"status": "failed", "reason": str(e)}, status=400)


@csrf_exempt
@require_http_methods(["GET"])
def health(request):
    """Health check endpoint"""
    return JsonResponse({"status": "healthy"})

