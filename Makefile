.PHONY: run test lint format typecheck check fix

run:
	uv run h2cli

test:
	uv run pytest tests/

# Run all checks (no modifications)
check:
	uv run ruff check src/ tests/
	uv run pyright src/

# Fix auto-fixable issues
fix:
	uv run ruff check --fix src/ tests/
	uv run pyright src/

format:
	un run ruff format src/ tests/

typecheck:
	uv run pyright src/

lint: fix typecheck
	@echo "✓ Linting complete"
