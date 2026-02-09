from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
import random
import json
from django.views.decorators.csrf import csrf_exempt
from .models import Commitment

# Public parameters
P = 2089
G = 2

# Client public key (registered)
Y = pow(G, 1008, P)  # client password = 1008


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
        
        # Save or update commitment
        Commitment.objects.update_or_create(
            client_id=client_id,
            defaults={"t": str(t)}
        )
        
        # Generate random challenge
        c = random.randint(1, P - 2)
        
        return JsonResponse({"c": c})
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
        
        # Retrieve commitment
        try:
            commitment = Commitment.objects.get(client_id=client_id)
            t = int(commitment.t)
        except Commitment.DoesNotExist:
            return JsonResponse({"status": "failed", "reason": "no commitment"}, status=400)
        
        # Verify Schnorr proof: g^s ≡ t * y^c (mod p)
        left = pow(G, s, P)
        right = (t * pow(Y, c, P)) % P
        
        if left == right:
            # Clean up commitment after successful verification
            commitment.delete()
            return JsonResponse({"status": "authenticated"})
        else:
            return JsonResponse({"status": "failed", "reason": "verification failed"})
    except Exception as e:
        return JsonResponse({"status": "failed", "reason": str(e)}, status=400)
