#!/usr/bin/env bash
# audit_redis.sh : audit de sécurité Redis, score /100
# Usage : sudo ./audit_redis.sh avant     (puis : sudo ./audit_redis.sh apres)
CONF="${REDIS_CONF:-/etc/redis/redis.conf}"
LABEL="${1:-audit}"
[ "$EUID" -eq 0 ] || { echo "Lancer avec sudo."; exit 1; }
exec > >(tee "audit_${LABEL}_$(hostname).txt") 2>&1

SCORE=0
cfg() { grep -Ei "^[[:space:]]*$1[[:space:]]" "$CONF" 2>/dev/null | tail -n1 \
        | sed -E 's/^[[:space:]]*[^[:space:]]+[[:space:]]+//' | tr -d '"'; }
b()   { "$@" >/dev/null 2>&1 && echo 1 || echo 0; }
chk() { # nom points ok(0/1) détail
  if [ "$3" = 1 ]; then SCORE=$((SCORE+$2)); printf '[ OK ] %-34s %2s/%-2s %s\n' "$1" "$2" "$2" "$4"
  else printf '[FAIL] %-34s  0/%-2s %s\n' "$1" "$2" "$4"; fi; }

PORT=$(cfg port); PORT=${PORT:-6379}
TLSPORT=$(cfg tls-port); TLSPORT=${TLSPORT:-0}
LP=$PORT; [ "$PORT" = 0 ] && LP=$TLSPORT
CLI="redis-cli -h 127.0.0.1 -p $LP"; [ "$PORT" = 0 ] && CLI="$CLI --tls --insecure"

echo "=== Audit Redis [$LABEL] : $(hostname) : $(date '+%F %T') ==="
echo "Config : $CONF | $(redis-server --version 2>/dev/null | cut -d' ' -f1-3)"
echo

# 1. Authentification
R=$($CLI ping 2>&1)
case "$R" in
  *PONG*) A=0; D="ping accepté sans mot de passe" ;;
  *NOAUTH*|*"uthentication required"*) A=1; D="authentification exigée" ;;
  *) if [ -n "$(cfg requirepass)" ]; then A=1; D="requirepass défini"; else A=0; D="aucun mot de passe trouvé"; fi ;;
esac
chk "Authentification" 15 $A "$D"

# 2. Comptes ACL
N=$(grep -hE '^user ' "$CONF" "$(cfg aclfile)" 2>/dev/null | grep -vc '^user default')
chk "Comptes ACL à droits limités" 10 "$(b test "$N" -ge 1)" "$N compte(s) hors default"

# 3. Écoute réseau
LISTEN=$(ss -H -tln "sport = :$LP" 2>/dev/null | awk '{print $4}' | tr '\n' ' ')
if [ -z "$LISTEN" ]; then B=0; D="service non détecté sur le port $LP"
elif echo "$LISTEN" | grep -Eq '(^| )(0\.0\.0\.0|\*|\[::\]):'; then B=0; D="écoute sur toutes les interfaces"
else B=1; D="écoute : $LISTEN"; fi
chk "Écoute réseau restreinte" 10 $B "$D"

# 4. protected-mode
PM=$(cfg protected-mode)
chk "protected-mode actif" 5 "$(b test "$PM" != no)" "protected-mode=${PM:-yes (défaut)}"

# 5-6. Pare-feu UFW
UA=0; UR=0
if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q '^Status: active'; then
  UA=1
  LC_ALL=C ufw status | grep -E "^$LP(/tcp)? +ALLOW" | grep -q Anywhere || UR=1
fi
chk "UFW actif" 5 $UA ""
chk "Port $LP non ouvert à tous (UFW)" 10 $UR "aucune règle 'Anywhere'"

# 7. TLS
chk "Chiffrement TLS (sans port clair)" 15 "$(b test "$TLSPORT" != 0 -a "$PORT" = 0)" "port=$PORT tls-port=$TLSPORT"

# 8. Commandes sensibles
RN=$(grep -Eic '^rename-command[[:space:]]+(CONFIG|FLUSHALL|FLUSHDB|DEBUG|KEYS)' "$CONF" 2>/dev/null)
DG=$(grep -h -- '-@dangerous' "$CONF" "$(cfg aclfile)" 2>/dev/null | wc -l)
chk "Commandes sensibles bloquées" 10 "$(b test "${RN:-0}" -ge 2 -o "$DG" -ge 1)" "rename-command=$RN, -@dangerous=$DG"

# 9. Utilisateur du processus
U=$(ps -o user= -C redis-server 2>/dev/null | head -1 | tr -d ' ')
chk "Redis non exécuté en root" 5 "$(b test -n "$U" -a "$U" != root)" "utilisateur : ${U:-inconnu}"

# 10. Permissions fichiers
DIR=$(cfg dir); DIR=${DIR:-/var/lib/redis}
PC=$(stat -c %a "$CONF" 2>/dev/null); PD=$(stat -c %a "$DIR" 2>/dev/null)
chk "Fichiers protégés (conf + données)" 5 "$(b test -n "$PC" -a "${PC: -1}" = 0 -a -n "$PD" -a "${PD: -1}" = 0)" "conf=$PC dir=$PD"

# 11. maxmemory
MM=$(cfg maxmemory)
chk "maxmemory défini" 5 "$(b test -n "$MM" -a "$MM" != 0)" "maxmemory=${MM:-non défini}"

# 12. Journalisation
LF=$(cfg logfile)
chk "Journalisation (logfile)" 5 "$(b test -n "$LF")" "logfile=${LF:-non défini}"

echo
echo "Info persistance : appendonly=$(cfg appendonly) | save=$(grep -E '^save ' "$CONF" 2>/dev/null | wc -l) règle(s)"
if   [ $SCORE -ge 80 ]; then L="BON"
elif [ $SCORE -ge 60 ]; then L="MOYEN"
elif [ $SCORE -ge 40 ]; then L="FAIBLE"
else L="CRITIQUE"; fi
echo "SCORE : $SCORE/100 : niveau $L"
