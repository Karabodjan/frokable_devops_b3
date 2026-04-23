# ─────────────────────────────────────────────────────────────────────────────
# Dockerfile — Backend Python/FastAPI
#
# CE FICHIER EST VOLONTAIREMENT VIDE.
# Votre mission : écrire le Dockerfile qui permet de conteneuriser cette API.
#
# Critères attendus :
#   - Image de base Python légère (python:3.12-slim)
#   - WORKDIR défini
#   - Dépendances installées depuis requirements.txt
#   - Code copié
#   - Port 8000 exposé
#   - Commande de démarrage : uvicorn main:app --host 0.0.0.0 --port 8000
#
# Bonus : implémenter un multi-stage build pour réduire la taille de l'image
# ─────────────────────────────────────────────────────────────────────────────


# Image de base
FROM python:3.12-slim AS builder

# Dossier de travail dans le conteneur
WORKDIR /backend

# Ne pas créer de fichiers pendant l'installation des dépendances
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── STAGE FINAL ────────────────────────────────────────────────────

FROM python:3.12-slim

WORKDIR /backend

COPY --from=builder /install /usr/local
COPY . .

EXPOSE 8000

# Commande de démarrage
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]