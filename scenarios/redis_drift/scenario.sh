#!/bin/sh
# Redis drift scenario script executed inside the target container.

while true; do
  SLEEP_TIME=$(( (RANDOM % 121) + 60 ))

  echo "[$(date)] --- scenario change start ---"

  if [ $((RANDOM % 2)) -eq 1 ]; then
    echo "[+] Redis running (6379 open)"
    redis-server --daemonize yes > /dev/null 2>&1
  else
    echo "[-] Redis stopped (6379 closed)"
    redis-cli shutdown > /dev/null 2>&1
  fi

  if [ $((RANDOM % 2)) -eq 1 ]; then
    echo "[+] SSH simulation start"
    nohup nc -lk -p 22 -e echo "SSH-2.0-OpenSSH_8.9p1" > /dev/null 2>&1 &
  else
    echo "[-] SSH simulation stop"
    pkill -f "nc -lk -p 22" > /dev/null 2>&1
  fi

  if [ $((RANDOM % 2)) -eq 1 ]; then
    echo "[+] HTTP simulation start"
    nohup nc -lk -p 80 -e echo -e "HTTP/1.1 200 OK\n\nMock Server" > /dev/null 2>&1 &
  else
    echo "[-] HTTP simulation stop"
    pkill -f "nc -lk -p 80" > /dev/null 2>&1
  fi

  echo "[$(date)] sleeping ${SLEEP_TIME}s before next change..."
  sleep $SLEEP_TIME
done
