# ============================================================
#  NAC -> Wazuh
#  Transforme les fichiers d'etat NAC (un par PC, multi-lignes
#  "cle : valeur", ecrases a chaque cycle) en un journal
#  consolide JSON en mode AJOUT, lisible proprement par l'agent
#  Wazuh.
#
#  A planifier toutes les 5 minutes via le Planificateur de
#  taches Windows, sur le DC ou atterrissent les fichiers.
# ============================================================

# ----------------------------------------------------------
# Dossier ou les PC ecrivent leurs fichiers d'etat
$Source = "C:\NACReports"
# Journal consolide que l'agent Wazuh va lire (mode ajout)
$Output = "C:\ReportsToWazhu\nac_consolidated.log"
# -----------------------------------------------------------

# Cree le dossier de sortie si besoin
$outDir = Split-Path -Parent $Output
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

Get-ChildItem -Path $Source -Filter *.txt -File | ForEach-Object {
    $data = [ordered]@{}

    # Parse chaque ligne "cle : valeur"
    Get-Content $_.FullName | ForEach-Object {
        if ($_ -match '^\s*(.+?)\s*:\s*(.+)$') {
            $key = ($matches[1].Trim() -replace '\s+', '_')   # "Windows 11" -> "Windows_11"
            $data[$key] = $matches[2].Trim()
        }
    }

    if ($data.Count -gt 0) {
        # Champs ajoutes pour Wazuh
        $data['log_type']     = 'nac'                          # sert a cibler les regles
        $data['source_file']  = $_.Name
        $data['collected_at'] = (Get-Date).ToString('s')

        # Une ligne JSON compacte, ajoutee au journal consolide
        $json = $data | ConvertTo-Json -Compress
        Add-Content -Path $Output -Value $json -Encoding UTF8
    }
}
