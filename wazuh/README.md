# Lab AD Blue Team / Wazuh

## Mise en place du lab

**LIRE ATTENTIVEMENT TOUTES LES ÉTAPES AVANT DE COMMENCER.**
**NE PAS FAIRE D'ACTIONS MANUELLES TELLES QUE RENOMMER LES MACHINES.**

### Vue générale

Le lab est constitué de 3 machines.

- **DC** : contrôleur de domaine Windows Server 2022, domaine `NEVASEC.LAB`, IP fixe `.200`, agent Wazuh installé
- **Wazuh VM** : Linux (Amazon Linux 2023), Wazuh all-in-one (manager + indexer + dashboard)
- **Kali Linux** : plateforme d'attaque

Toutes les machines sont dans le même sous-réseau via le réseau NAT de l'hyperviseur.

---

### Réseau

Toutes les VM doivent être sur le même réseau NAT.

- **VirtualBox** : NAT Network (Réseau NAT)
  - Si aucun n'existe : `File` > `Tools` > `Network manager` > onglet `NAT Networks` > `Create`
  - Assigner ce NAT Network à chaque VM dans ses paramètres réseau
- **VMware** : Custom (VMNet8)
  - Assigner `VMnet8` à chaque VM dans ses paramètres réseau

Le DC prend l'IP fixe `.200` (assignée par le script).

---

### 1. Wazuh VM

1. Télécharger l'[OVA](https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html).
2. Importer l'OVA dans l'hyperviseur
   - VirtualBox : `File` > `Import Appliance`
   - VMware : `File` > `Open`
3. Avant de démarrer, vérifier le réseau : NAT Network (VirtualBox) ou VMNet8 (VMware)
4. **VirtualBox uniquement** : dans les paramètres d'affichage, passer le contrôleur graphique sur `VMSVGA`
5. Démarrer la VM. Identifiants : `wazuh-user` / `wazuh`
6. Noter l'adresse IP `ip a`

Ressources nécessaires : **4 vCPU, 8 GB RAM, 50 GB disque**.

---

### 2. DC (Windows Server 2022)

1. Télécharger l'[ISO](https://www.microsoft.com/fr-fr/evalcenter/download-windows-server-2022) **EN FRANÇAIS**
2. Créer la VM dans l'hyperviseur en la nommant DC.
  - Pour VirtualBox, ajouter le fichier ISO. ⚠️IMPORTANT⚠️ : **Décocher la case `Proceed with Unattended Installation`**
  - Pour VMware, **ne pas ajouter le fichier ISO à la création de la VM, choisir `I will install the operating system later`**. Puis ajouter l'ISO dans le lecteur CD quand la VM est créée.
3. Lancer la VM et installer **Windows Server 2022 Standard (Expérience de bureau)**
4. Choisir l'installation personnalisée, sélectionner le disque, laisser Windows s'installer et redémarrer
5. Mot de passe Administrateur local : `R00tR00t`
6. Installer les VM Tools / Guest Additions, redémarrer
7. Ouvrir PowerShell en admin :
```powershell
powershell -ep bypass
(iwr -useb "https://raw.githubusercontent.com/NevaSec/ADLab/main/wazuh/DC.ps1") | iex; Invoke-LabSetup
```
8. Le script redémarre le serveur automatiquement. Répéter l'étape 7.
9. Au second redémarrage, se connecter avec `NEVASEC\Administrateur` (`R00tR00t`) et relancer le script une dernière fois (étapes 7).

---

### 3. Kali Linux

1. Télécharger l'image [VM Kali](https://www.kali.org/get-kali/#kali-virtual-machines)
2. Importer l'image dans l'hyperviseur
3. Ajuster la carte réseau : NAT Network (VirtualBox) ou VMNet8 (VMware)
4. Démarrer, se connecter : `kali` / `kali`
5. Configurer le clavier français :
```bash
setxkbmap fr
sudo nano /etc/default/keyboard   # changer XKBLAYOUT="us" en XKBLAYOUT="fr"
```
6. Mettre à jour et installer les outils :
```bash
sudo apt update
sudo apt install -y kali-root-login bloodhound-python bloodhound
```
7. Définir un mot de passe root :
```bash
sudo passwd root
```
8. Redémarrer et se connecter en `root`
9. Vérifier que tout est ok puis faire un snapshot

---

### Récapitulatif des identifiants

| Machine  | Compte                    | Mot de passe |
|----------|---------------------------|--------------|
| DC       | `Administrateur` (local & domaine)  | `R00tR00t`   |
| Wazuh VM (SSH) | `wazuh-user`        | `wazuh`      |
| Wazuh VM (dashboard) | `admin`      | `admin`      |
| Kali     | `kali`                    | `kali`       |
| Kali     | `root`                    | défini par vous |


---

### Vérifications finales

- [ ] Kali peut pinguer le DC (`.200`) et l'IP Wazuh
- [ ] Snapshot de chaque VM fait
