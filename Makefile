.PHONY: up down build logs shell db-shell health clean test-upload

up:
	docker compose up -d --build
	@echo "API      → http://localhost:8000/docs"

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f api

shell:
	docker compose exec api bash

db-shell:
	docker compose exec db psql -U smscope -d securemailscope

health:
	@curl -s http://localhost:8000/api/health | python3 -m json.tool

# Upload a capture: make test-upload PCAP=sample_pcaps/foo.pcap
test-upload:
	@curl -s -X POST http://localhost:8000/api/captures \
		-F "file=@$(PCAP)" | python3 -m json.tool

clean:
	docker compose down -v
