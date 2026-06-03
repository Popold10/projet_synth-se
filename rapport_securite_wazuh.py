#!/usr/bin/env python3
"""
Rapport de securite Wazuh + Ollama
----------------------------------
Genere a la demande, via une page web, un rapport d'analyse des
tentatives d'attaque et des problemes de connexion au domaine AD.

Principe :
  1. Interroge l'indexeur Wazuh (OpenSearch) sur une fenetre de temps.
  2. AGREGE cote serveur (echecs par utilisateur / IP / code d'erreur).
  3. Envoie cette synthese compacte a Ollama, qui redige le rapport.
  4. Affiche le tout sur une page web.

Dependances :  pip3 install flask requests
Lancement   :  python3 rapport_securite_wazuh.py
Acces       :  http://127.0.0.1:8080/
"""

import datetime
import requests
import urllib3
from flask import Flask, request, render_template_string

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===========================================================================
# CONFIGURATION  ->  a adapter a ton environnement
# ===========================================================================
OPENSEARCH_URL  = "https://localhost:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "CHANGE_ME"          # mot de passe de l'indexeur Wazuh
INDEX           = "wazuh-alerts-*"
VERIFY_SSL      = False                # certificat auto-signe Wazuh
TIME_FIELD      = "timestamp"          # passe a "@timestamp" si besoin

OLLAMA_URL      = "http://localhost:11434/api/generate"
OLLAMA_MODEL    = "llama3.2:3b"        # adapte au modele que tu fais tourner

LISTEN_HOST     = "127.0.0.1"          # NE PAS exposer publiquement
LISTEN_PORT     = 8080

# Event IDs d'authentification qui nous interessent
AUTH_EVENT_IDS  = ["4624", "4625", "4768", "4771", "4776", "4740"]
FAIL_EVENT_IDS  = ["4625", "4771", "4776"]

# ===========================================================================
# 1. Recuperation + agregation des alertes depuis l'indexeur
# ===========================================================================
def fetch_aggregates(hours):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {TIME_FIELD: {"gte": f"now-{hours}h"}}},
                    {"terms": {"data.win.system.eventID": AUTH_EVENT_IDS}},
                ]
            }
        },
        "aggs": {
            "par_eventid": {
                "terms": {"field": "data.win.system.eventID", "size": 20}
            },
            "echecs_par_user": {
                "filter": {"terms": {"data.win.system.eventID": FAIL_EVENT_IDS}},
                "aggs": {"users": {"terms": {
                    "field": "data.win.eventdata.targetUserName", "size": 15}}},
            },
            "echecs_par_ip": {
                "filter": {"terms": {"data.win.system.eventID": FAIL_EVENT_IDS}},
                "aggs": {"ips": {"terms": {
                    "field": "data.win.eventdata.ipAddress", "size": 15}}},
            },
            "par_rule": {"terms": {"field": "rule.id", "size": 15}},
            "codes_erreur": {
                "terms": {"field": "data.win.eventdata.status", "size": 15}
            },
        },
    }
    r = requests.get(
        f"{OPENSEARCH_URL}/{INDEX}/_search",
        json=query,
        auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        verify=VERIFY_SSL,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


# ===========================================================================
# 2. Mise en forme de la synthese (ce qui sera envoye au LLM)
# ===========================================================================
EVENT_LEGEND = {
    "4624": "ouverture de session reussie",
    "4625": "echec d'ouverture de session",
    "4768": "TGT Kerberos (connexion domaine)",
    "4771": "echec de pre-auth Kerberos",
    "4776": "validation NTLM",
    "4740": "compte verrouille",
}
CODE_LEGEND = {
    "0x18": "mauvais mot de passe",
    "0x12": "compte desactive/verrouille",
    "0x6":  "utilisateur inconnu",
    "0x25": "decalage d'horloge (probleme technique)",
    "0x17": "mot de passe expire",
    "0x0":  "succes",
}


def build_summary(resp, hours):
    aggs = resp.get("aggregations", {})
    total = resp.get("hits", {}).get("total", 0)
    if isinstance(total, dict):
        total = total.get("value", 0)

    def buckets(*path):
        node = aggs
        for p in path:
            node = node.get(p, {})
        return node.get("buckets", [])

    out = [f"Fenetre analysee : {hours} dernieres heures",
           f"Total d'evenements d'authentification : {total}", ""]

    out.append("Repartition par type d'evenement :")
    for b in buckets("par_eventid", "buckets"):
        eid = b["key"]
        out.append(f"  - {eid} ({EVENT_LEGEND.get(eid, '?')}) : {b['doc_count']}")

    out.append("\nTop utilisateurs avec echecs :")
    ub = buckets("echecs_par_user", "users", "buckets")
    out += [f"  - {b['key']} : {b['doc_count']} echecs" for b in ub] or ["  (aucun)"]

    out.append("\nTop IP sources avec echecs :")
    ib = buckets("echecs_par_ip", "ips", "buckets")
    out += [f"  - {b['key']} : {b['doc_count']} echecs" for b in ib] or ["  (aucune)"]

    out.append("\nCodes d'erreur rencontres :")
    cb = buckets("codes_erreur", "buckets")
    out += [f"  - {b['key']} ({CODE_LEGEND.get(b['key'], '?')}) : {b['doc_count']}"
            for b in cb] or ["  (aucun)"]

    return "\n".join(out)


# ===========================================================================
# 3. Demande de redaction du rapport a Ollama
# ===========================================================================
PROMPT_TEMPLATE = """Tu es analyste SOC. A partir de la synthese d'alertes Wazuh ci-dessous \
(authentifications au domaine Active Directory), redige un rapport de securite clair, en francais.

Legende des codes d'echec : 0x18 = mauvais mot de passe, 0x12 = compte desactive/verrouille, \
0x6 = utilisateur inconnu, 0x25 = decalage d'horloge (probleme technique, PAS une attaque), \
0x17 = mot de passe expire.

REGLES STRICTES (a respecter imperativement) :
- N'affirme RIEN qui ne soit pas explicitement dans les donnees. N'invente aucun chiffre, aucun utilisateur, aucune IP.
- Compte le nombre d'utilisateurs distincts et d'IP distinctes dans la liste des echecs, et raisonne dessus :
  * BRUTE-FORCE = plusieurs echecs concentres sur UN SEUL compte.
  * PASSWORD SPRAY = plusieurs comptes DISTINCTS vises (3 utilisateurs differents ou plus), souvent depuis une meme IP.
  * S'il n'y a qu'UN SEUL utilisateur dans la liste des echecs, c'est du BRUTE-FORCE, jamais du password spray. \
N'ecris JAMAIS "differents comptes" ou "plusieurs comptes" dans ce cas.
- Si une categorie est vide, dis-le simplement (ex: "aucune tentative suspecte detectee").

Structure le rapport ainsi :
1. Resume en une ou deux phrases, en precisant le nombre d'echecs et le nombre d'utilisateurs/IP distincts concernes.
2. Tentatives suspectes / signaux d'attaque : qualifie correctement (brute-force vs password spray selon les regles ci-dessus), cite les utilisateurs et IP exacts.
3. Problemes de connexion benins (mots de passe expires, decalage d'horloge, comptes desactives).
4. Recommandations concretes.

SYNTHESE :
{summary}
"""


def ask_ollama(summary):
    r = requests.post(
        OLLAMA_URL,
        json={"model": OLLAMA_MODEL,
              "prompt": PROMPT_TEMPLATE.format(summary=summary),
              "stream": False},
        timeout=300,   # un petit modele sur CPU peut etre lent
    )
    r.raise_for_status()
    return r.json().get("response", "(pas de reponse du modele)")


# ===========================================================================
# 4. Page web
# ===========================================================================
app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>Rapport securite Wazuh</title>
<style>
 body{font-family:system-ui,Arial,sans-serif;max-width:900px;margin:2rem auto;
      padding:0 1rem;color:#1a2332;}
 h1{border-bottom:3px solid #2f5fff;padding-bottom:.4rem;}
 h2{margin-top:1.6rem;}
 form{margin:1rem 0;}
 select,button{font-size:1rem;padding:.4rem .6rem;border-radius:6px;}
 button{background:#2f5fff;color:#fff;border:0;cursor:pointer;margin-left:.4rem;}
 .report{background:#f6f8fc;border:1px solid #d7e0f0;border-radius:8px;
         padding:1.2rem;white-space:pre-wrap;line-height:1.55;}
 .summary{background:#1a2332;color:#d7e0f0;border-radius:8px;padding:1rem;
          font-family:monospace;white-space:pre;overflow:auto;font-size:.85rem;}
 .meta{color:#5a6b85;font-size:.85rem;}
 .err{color:#c0392b;font-weight:bold;}
</style></head><body>
<h1>Rapport securite &mdash; connexions au domaine</h1>
<form method="get">
  Fenetre :
  <select name="hours">
    <option value="6"{{ ' selected' if hours==6 else '' }}>6 h</option>
    <option value="24"{{ ' selected' if hours==24 else '' }}>24 h</option>
    <option value="72"{{ ' selected' if hours==72 else '' }}>72 h</option>
    <option value="168"{{ ' selected' if hours==168 else '' }}>7 jours</option>
  </select>
  <button type="submit">Generer le rapport</button>
</form>
{% if error %}<p class="err">Erreur : {{ error }}</p>{% endif %}
{% if report %}
  <p class="meta">Genere le {{ now }} &mdash; modele {{ model }}</p>
  <h2>Analyse</h2>
  <div class="report">{{ report }}</div>
  <h2>Donnees agregees (source du rapport)</h2>
  <div class="summary">{{ summary }}</div>
{% endif %}
</body></html>"""


@app.route("/")
def rapport():
    report = summary = error = None
    try:
        hours = int(request.args.get("hours", 24))
    except ValueError:
        hours = 24
    if request.args.get("hours"):
        try:
            resp = fetch_aggregates(hours)
            summary = build_summary(resp, hours)
            report = ask_ollama(summary)
        except Exception as e:
            error = str(e)
    return render_template_string(
        PAGE, report=report, summary=summary, error=error, hours=hours,
        now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        model=OLLAMA_MODEL,
    )


if __name__ == "__main__":
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
