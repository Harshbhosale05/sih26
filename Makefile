.PHONY: up down build logs shell db-shell health clean test-upload web corpus train validate

up:
	docker compose up -d --build
	@echo "API      → http://localhost:8000/docs"
	@echo "UI       → http://localhost:5173"

# Run the React dashboard locally instead of in docker (needs Node 20+).
web:
	cd frontend && npm install && npm run dev

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

# Labelled corpus for the session risk classifier (pure Python, no Docker).
corpus:
	python3 -m testbed.synthetic.corpus --sessions 1600 --seed 7

# Train the risk classifier through the production pipeline (tshark in the API image).
# Writes backend/app/ml/artifacts/risk_model.{joblib,json}; re-run analysis afterwards.
train: corpus
	docker compose run --rm --no-deps -v "$(PWD)/testbed:/testbed:ro" \
		-v "$(PWD)/backend/app/ml/artifacts:/out" api \
		python -m app.ml.train_risk --corpus /testbed/output/corpus --out /out

validate:
	python3 scripts/validate.py
