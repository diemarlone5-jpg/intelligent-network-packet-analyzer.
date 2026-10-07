# Image de l'application web (mode consultation / historique).
#
# IMPORTANT : cette image sert a heberger l'interface en ligne, en mode
# consultation. La CAPTURE reseau n'est pas possible dans un conteneur distant :
# elle exige un acces au pilote reseau de la machine, donc Npcap (Windows) ou
# libpcap (Linux) sur le poste de l'utilisateur. Le site deploye lit
# l'historique enregistre dans Supabase.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=prod \
    APP_MODE=cloud

WORKDIR /app

# Dependances systeme minimales : tcpdump n'est PAS installe volontairement,
# car il ne servirait a rien sans acces au materiel reseau.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY schema ./schema
COPY run.py .
COPY pyproject.toml .

# Utilisateur non privilegie : un conteneur web n'a aucune raison de tourner
# en root.
RUN useradd --create-home --shell /bin/bash analyzer \
    && mkdir -p /app/data \
    && chown -R analyzer:analyzer /app
USER analyzer

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/status || exit 1

CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "8000"]
