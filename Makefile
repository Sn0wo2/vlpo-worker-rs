.PHONY: deploy
.PHONY: secrets

deploy:
	@echo Running deploy tool...
	@python ./scripts/deploy.py

secrets:
	@echo Generating secrets tool...
	@python ./scripts/secrets.py
