.PHONY: run build down test logs clean lint typecheck

## Start the service (builds if needed)
run:
	docker-compose up --build

## Start in detached mode
up:
	docker-compose up --build -d

## Stop and remove containers
down:
	docker-compose down

## Stop and remove containers + volumes (wipes data)
clean:
	docker-compose down -v

## Run the test suite inside Docker
test:
	docker-compose run --rm api pytest -v --cov=app --cov-report=term-missing

## Run the test suite locally
test-local:
	pytest -v --cov=app --cov-report=term-missing

## Run linting
lint:
	ruff check app/ tests/
	ruff format --check app/ tests/

## Run type checking
typecheck:
	mypy app/ --ignore-missing-imports

## Fix lint issues automatically
fix:
	ruff check app/ tests/ --fix
	ruff format app/ tests/

## Tail logs
logs:
	docker-compose logs -f api

## Open Swagger UI in the browser
docs:
	xdg-open http://localhost:8001/docs 2>/dev/null || open http://localhost:8001/docs
