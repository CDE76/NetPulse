# NetPulse IPAM — Scanner Réseau Local IPv4 & Gestion d'Adressage

Application web légère (sans dépendances Python externes) permettant de scanner les réseaux/sous-réseaux locaux, résoudre les noms DNS, lire la table ARP (adresses MAC + constructeurs), scanner les ports TCP courants, gérer l'historique des scans, ré-importer des plans CSV et générer des rapports PDF.

## Déploiement sur Portainer (via Dépôt Git)

1. Dans **Portainer**, allez dans **Stacks** → **+ Add stack**.
2. Donnez un nom à la stack (ex: `netpulse-ipam`).
3. Dans **Build method**, sélectionnez **Repository**.
4. Renseignez :
   - **Repository URL** : l'URL de votre dépôt Git
   - **Repository reference** : `refs/heads/main`
   - **Compose path** : `docker-compose.yml`
5. Cliquez sur **Deploy the stack**.
6. Accédez à l'application sur `http://<IP-DE-VOTRE-SERVEUR-DOCKER>:8080`.

> **Note sur `network_mode: host`** : Le fichier `docker-compose.yml` utilise `network_mode: host` afin que le conteneur puisse scanner directement le sous-réseau physique du serveur Docker et lire la table ARP locale (`/proc/net/arp`) pour remonter les adresses MAC des équipements. Toutes vos sauvegardes et votre historique sont conservés de manière persistante dans le volume Docker `ipam_data` (`/data/ipam.db`).
