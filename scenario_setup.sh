#!/bin/bash

# 순서
# scenario.sh를 컨테이너 내부 /data/ 폴더로 복사
# 복사된 파일에 실행 권한 부여
# 컨테이너 내부에서 해당 스크립트를 백그라운드로 실행

docker cp ./scenario.sh mini-asm-redis-target:/data/scenario.sh
docker exec mini-asm-redis-target chmod +x /data/scenario.sh
docker exec -d mini-asm-redis-target sh /data/scenario.sh

echo "시나리오가 mini-asm-redis-target 컨테이너에 전달되어 실행 중입니다."