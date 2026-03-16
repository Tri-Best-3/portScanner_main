#!/bin/sh
# 이 스크립트는 컨테이너 내부(/data)에서 실행됨.

# 사용법
# 1. docker compose up -d로 전체 컨테이너가 실행된 상태에서 수행
# 2. 로컬 터미널에서 주입 스크립트 실행
# >>> ./scenario_setup.sh
# 3. 시나리오 작동 확인 명령어 3가지
# >>> docker exec -it mini-asm-redis-target sh
# >>> docker exec -it mini-asm-redis-target watch -n 2 "netstat -tpln"
# >>> netstat -tuln 또는 ss -tuln 명령어로 포트 상태 확인 가능

while true; do
  # 1. 대기 시간 랜덤 설정 (60초 ~ 180초)
  SLEEP_TIME=$(( (RANDOM % 121) + 60 ))
  
  echo "[$(date)] --- 시나리오 변화 시작 ---"

  # 2. Redis(6379) 상태 변경 (필수 타겟)
  if [ $((RANDOM % 2)) -eq 1 ]; then
    echo "[+] Redis 실행 (6379 Open)"
    redis-server --daemonize yes > /dev/null 2>&1
  else
    echo "[-] Redis 중지 (6379 Closed)"
    redis-cli shutdown > /dev/null 2>&1
  fi

  # 3. 추가 서비스 랜덤 상태 변경 (SSH, HTTP)
  # 해당 부분 포트 수정 및 서비스 시뮬레이션은 실제 환경에 맞게 조정 가능
  # 컨테이너 내부에 해당 바이너리가 없을 경우를 대비해 에러는 무시하도록 설정
  
  # 예: SSH (22번 포트)
  if [ $((RANDOM % 2)) -eq 1 ]; then
    echo "[+] SSH 서비스 시뮬레이션 시작"
    # 실제 SSHD가 없다면 nc(netcat)를 이용해 포트만 열어두어도 충분히 시뮬레이션 가능
    nohup nc -lk -p 22 -e echo "SSH-2.0-OpenSSH_8.9p1" > /dev/null 2>&1 &
  else
    echo "[-] SSH 서비스 시뮬레이션 종료"
    pkill -f "nc -lk -p 22" > /dev/null 2>&1
  fi

  # 예: HTTP (80번 포트)
  if [ $((RANDOM % 2)) -eq 1 ]; then
    echo "[+] HTTP 서비스 시뮬레이션 시작"
    nohup nc -lk -p 80 -e echo -e "HTTP/1.1 200 OK\n\nMock Server" > /dev/null 2>&1 &
  else
    echo "[-] HTTP 서비스 시뮬레이션 종료"
    pkill -f "nc -lk -p 80" > /dev/null 2>&1
  fi

  echo "[$(date)] 다음 변화까지 ${SLEEP_TIME}초 대기..."
  sleep $SLEEP_TIME
done