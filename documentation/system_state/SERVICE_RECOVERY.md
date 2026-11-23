# Attack Correlation Engine - Service Recovery

## Project Paths

Project: /home/kali/attack-correlation-engine
Virtual Environment: /home/kali/attack-correlation-engine/venv
Elasticsearch: /home/kali/elasticsearch-9.4.2

## Services

| Service | Port | Runtime |
|---|---:|---|
| Elasticsearch | 9200 | Bundled JDK |
| Live Analyst API | 8000 | System Python 3.10 |
| Live Incident API | 8001 | System Python 3.10 |
| Evaluation Analyst API | 8002 | Project venv |
| Demo Incident API | 8003 | Project venv |

## Recovery Commands

### Elasticsearch

    cd /home/kali/elasticsearch-9.4.2
    nohup ./bin/elasticsearch > logs/elasticsearch-recovery.log 2>&1 &

### Live Analyst API

    cd /home/kali/attack-correlation-engine
    nohup /usr/bin/python3.10 -m uvicorn analyst_api:app --host 0.0.0.0 --port 8000 > logs/analyst-live.log 2>&1 &

### Live Incident API

    cd /home/kali/attack-correlation-engine
    nohup /usr/bin/python3.10 -m uvicorn incident_api:app --host 0.0.0.0 --port 8001 > logs/incident-live.log 2>&1 &

### Evaluation Analyst API

    cd /home/kali/attack-correlation-engine
    ANALYST_VIEW_DIR=evaluation/analyst_view nohup ./venv/bin/uvicorn analyst_api:app --host 0.0.0.0 --port 8002 > logs/analyst-evaluation.log 2>&1 &

### Demo Incident API

    cd /home/kali/attack-correlation-engine
    DEMO_MODE=true nohup ./venv/bin/uvicorn incident_api:app --host 0.0.0.0 --port 8003 > logs/incident-demo.log 2>&1 &

## Health Checks

    for port in 8000 8001 8002 8003; do
      echo "PORT $port"
      curl -s http://localhost:$port/health
      echo
    done

    curl -s http://localhost:9200

## Important Notes

- Never start a second instance if the port is already occupied.
- Port 8001 is the live Incident API. Do not send evaluation data to it.
- Port 8003 runs in DEMO_MODE.
- Port 8002 uses evaluation/analyst_view.
- Additional environment variables of the original live processes have not been verified.
